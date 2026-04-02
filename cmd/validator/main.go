package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/venatiodecorus/proxy-scanner/internal/database"
	"github.com/venatiodecorus/proxy-scanner/internal/proxy"
	"github.com/venatiodecorus/proxy-scanner/internal/scanner"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("validator failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	// Configuration from environment
	scanInput := envOrDefault("SCAN_INPUT", "/data/candidates.json")
	dbPath := envOrDefault("DB_PATH", "/data/proxies.db")
	geoipCityDB := envOrDefault("GEOIP_CITY_DB", "/geoip/GeoLite2-City.mmdb")
	geoipASNDB := envOrDefault("GEOIP_ASN_DB", "/geoip/GeoLite2-ASN.mmdb")
	workers := envOrDefaultInt("WORKERS", 500)
	timeout := envOrDefaultInt("TIMEOUT", 10)
	testURL := envOrDefault("TEST_URL", "http://httpbin.org/ip")
	originIP := envOrDefault("ORIGIN_IP", "")

	// Auto-detect egress IP if not explicitly set
	if originIP == "" {
		logger.Info("ORIGIN_IP not set, auto-detecting egress IP...")
		detected, err := detectEgressIP(logger)
		if err != nil {
			logger.Warn("failed to auto-detect egress IP, anonymity detection will be limited", "error", err)
		} else {
			originIP = detected
			logger.Info("detected egress IP", "ip", originIP)
		}
	}

	logger.Info("starting validator",
		"scan_input", scanInput,
		"db_path", dbPath,
		"geoip_city_db", geoipCityDB,
		"geoip_asn_db", geoipASNDB,
		"workers", workers,
		"timeout", timeout,
		"test_url", testURL,
		"origin_ip", originIP,
	)

	// Setup context with graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	// Open database
	db, err := database.Open(dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	// Start scan run
	runID, err := db.StartScanRun()
	if err != nil {
		return fmt.Errorf("starting scan run: %w", err)
	}
	logger.Info("started scan run", "run_id", runID)

	// Mark all existing proxies as dead — only freshly validated ones survive
	if err := db.MarkAllDead(); err != nil {
		return fmt.Errorf("marking proxies dead: %w", err)
	}

	// Initialize GeoIP (optional — gracefully degrades if DBs not found)
	geoip, err := proxy.NewGeoIPLookup(proxy.GeoIPConfig{
		CityDBPath: geoipCityDB,
		ASNDBPath:  geoipASNDB,
	})
	if err != nil {
		logger.Warn("geoip databases not available, skipping geo tagging", "error", err)
	}
	if geoip != nil {
		defer geoip.Close()
		logger.Info("geoip databases loaded")
	}

	// Configure checker
	checkerCfg := proxy.CheckerConfig{
		Timeout:  time.Duration(timeout) * time.Second,
		TestURL:  testURL,
		OriginIP: originIP,
		Logger:   logger,
	}
	checker := proxy.NewChecker(checkerCfg)

	// Stream-parse masscan output. This uses a streaming JSON decoder so we
	// never hold the entire file in memory — critical for large scan outputs
	// (1GB+) on memory-constrained hosts.
	logger.Info("streaming scan results", "file", scanInput)
	candidateStream, countCh, parseErrCh := scanner.ParseFileStream(scanInput, logger)

	// Worker pool
	var verified atomic.Int64
	var processed atomic.Int64
	var total atomic.Int64

	workerCh := make(chan proxy.Candidate, workers*2)
	var wg sync.WaitGroup

	// Progress reporter
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p := processed.Load()
				v := verified.Load()
				t := total.Load()
				var pct float64
				if t > 0 {
					pct = float64(p) / float64(t) * 100
				}
				logger.Info("progress",
					"processed", p,
					"total", t,
					"percent", fmt.Sprintf("%.1f%%", pct),
					"verified", v,
				)
			}
		}
	}()

	// Start workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for candidate := range workerCh {
				if ctx.Err() != nil {
					return
				}

				results := checker.Check(ctx, candidate)
				for _, result := range results {
					if !result.Alive {
						continue
					}

					// GeoIP lookup
					geo := geoip.Lookup(result.Candidate.IP)

					p := &proxy.Proxy{
						IP:        result.Candidate.IP,
						Port:      result.Candidate.Port,
						Protocol:  result.Protocol,
						Anonymity: result.Anonymity,
						Country:   geo.Country,
						City:      geo.City,
						ASN:       geo.ASN,
						ASNOrg:    geo.ASNOrg,
						LatencyMs: result.LatencyMs,
						Alive:     true,
					}

					if err := db.UpsertProxy(p); err != nil {
						logger.Error("failed to upsert proxy",
							"ip", p.IP,
							"port", p.Port,
							"error", err,
						)
						continue
					}

					verified.Add(1)
				}

				processed.Add(1)
			}
		}()
	}

	// Feed candidates from the streaming parser directly to workers.
	// The parser sends candidates one at a time as it reads them from disk,
	// so memory usage stays constant regardless of file size.
	logger.Info("starting validation", "workers", workers)
	for candidate := range candidateStream {
		select {
		case workerCh <- candidate:
		case <-ctx.Done():
			// Drain remaining candidates from the stream to let the parser goroutine exit.
			for range candidateStream {
			}
		}
	}
	close(workerCh)

	// Collect parse results
	totalCandidates := <-countCh
	total.Store(int64(totalCandidates))
	if parseErr := <-parseErrCh; parseErr != nil {
		return fmt.Errorf("parsing scan results: %w", parseErr)
	}

	logger.Info("parsed candidates", "count", totalCandidates)

	if totalCandidates == 0 {
		logger.Info("no candidates to validate, exiting")
		if err := db.FinishScanRun(runID, 0, 0, "completed"); err != nil {
			return fmt.Errorf("finishing scan run: %w", err)
		}
		return nil
	}

	// Wait for workers to finish
	wg.Wait()

	totalVerified := int(verified.Load())
	status := "completed"
	if ctx.Err() != nil {
		status = "interrupted"
	}

	// Finish scan run
	if err := db.FinishScanRun(runID, totalCandidates, totalVerified, status); err != nil {
		return fmt.Errorf("finishing scan run: %w", err)
	}

	logger.Info("validation complete",
		"status", status,
		"candidates", totalCandidates,
		"verified", totalVerified,
		"run_id", runID,
	)

	return nil
}

// detectEgressIP discovers the node's public egress IP by querying external services.
// Tries multiple providers for redundancy.
func detectEgressIP(logger *slog.Logger) (string, error) {
	providers := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
		"https://checkip.amazonaws.com",
	}

	client := &http.Client{Timeout: 10 * time.Second}

	for _, url := range providers {
		resp, err := client.Get(url)
		if err != nil {
			logger.Debug("egress IP provider failed", "url", url, "error", err)
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		if err != nil {
			continue
		}
		ip := strings.TrimSpace(string(body))
		// Basic validation — should look like an IP
		if len(ip) >= 7 && len(ip) <= 45 && !strings.Contains(ip, " ") {
			return ip, nil
		}
	}

	return "", fmt.Errorf("all egress IP providers failed")
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrDefaultInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

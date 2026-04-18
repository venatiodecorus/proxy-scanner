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

	"github.com/venatiodecorus/proxy-scanner/internal/blocklist"
	"github.com/venatiodecorus/proxy-scanner/internal/database"
	"github.com/venatiodecorus/proxy-scanner/internal/proxy"
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
	dbPath := envOrDefault("DB_PATH", "/data/proxies.db")
	geoipCityDB := envOrDefault("GEOIP_CITY_DB", "/geoip/GeoLite2-City.mmdb")
	geoipASNDB := envOrDefault("GEOIP_ASN_DB", "/geoip/GeoLite2-ASN.mmdb")
	workers := envOrDefaultInt("WORKERS", 500)
	timeout := envOrDefaultInt("TIMEOUT", 10)
	testURL := envOrDefault("TEST_URL", "http://httpbin.org/ip")
	originIP := envOrDefault("ORIGIN_IP", "")
	skipBlocklist := envOrDefaultBool("SKIP_BLOCKLIST", false)
	batchSize := envOrDefaultInt("BATCH_SIZE", 1000)

	originIP, err := resolveOriginIP(logger, originIP)
	if err != nil && originIP == "" {
		logger.Warn("failed to auto-detect egress IP, anonymity detection will be limited", "error", err)
	}

	logger.Info("starting validator",
		"db_path", dbPath,
		"geoip_city_db", geoipCityDB,
		"geoip_asn_db", geoipASNDB,
		"workers", workers,
		"timeout", timeout,
		"test_url", testURL,
		"origin_ip", originIP,
		"skip_blocklist", skipBlocklist,
		"batch_size", batchSize,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	db, err := database.Open(dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	reset, err := db.ResetProcessingCandidates()
	if err != nil {
		return fmt.Errorf("resetting processing candidates: %w", err)
	}
	if reset > 0 {
		logger.Info("reset processing candidates from previous run", "count", reset)
	}

	startID, err := db.StartScanRun()
	if err != nil {
		return fmt.Errorf("starting scan run: %w", err)
	}
	logger.Info("started scan run", "run_id", startID)

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

	checkerCfg := proxy.CheckerConfig{
		Timeout:  time.Duration(timeout) * time.Second,
		TestURL:  testURL,
		OriginIP: originIP,
		Logger:   logger,
	}
	checker := proxy.NewChecker(checkerCfg)

	var blChecker *blocklist.Checker
	if !skipBlocklist {
		blChecker = blocklist.NewChecker(blocklist.WithLogger(logger))
		logger.Info("blocklist checking enabled")
	} else {
		logger.Info("blocklist checking disabled")
	}

	var verified atomic.Int64
	var processed atomic.Int64
	var total atomic.Int64

	workerCh := make(chan proxy.CandidateEntry, workers*2)
	var wg sync.WaitGroup

	progressTicker := time.NewTicker(30 * time.Second)
	defer progressTicker.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-progressTicker.C:
				p := processed.Load()
				v := verified.Load()
				t := total.Load()
				pending, _ := db.PendingCandidateCount()
				var pct float64
				if t > 0 {
					pct = float64(p) / float64(t) * 100
				}
				logger.Info("progress",
					"processed", p,
					"total", t,
					"percent", fmt.Sprintf("%.1f%%", pct),
					"verified", v,
					"pending_in_queue", pending,
				)
			}
		}
	}()

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for entry := range workerCh {
				if ctx.Err() != nil {
					return
				}

				candidate := proxy.Candidate{IP: entry.IP, Port: entry.Port}
				results := checker.Check(ctx, candidate)

				for _, result := range results {
					if !result.Alive {
						continue
					}

					geo := geoip.Lookup(result.Candidate.IP)

					p := &proxy.Proxy{
						IP:              result.Candidate.IP,
						Port:            result.Candidate.Port,
						Protocol:        result.Protocol,
						Anonymity:       result.Anonymity,
						Country:         geo.Country,
						City:            geo.City,
						ASN:             geo.ASN,
						ASNOrg:          geo.ASNOrg,
						ExitIP:          result.ExitIP,
						LatencyMs:       result.LatencyMs,
						SupportsConnect: result.SupportsConnect,
						TLSInsecure:     result.TLSInsecure,
						Alive:           true,
					}

					if blChecker != nil {
						blResult := blChecker.Check(ctx, p.IP)
						p.Blocklisted = blResult.Listed
						p.Blocklists = blResult.BlocklistsString()
						if p.Blocklisted {
							logger.Debug("proxy on blocklist",
								"ip", p.IP,
								"port", p.Port,
								"blocklists", p.Blocklists,
							)
						}
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

				if err := db.DeleteCandidate(entry.ID); err != nil {
					logger.Error("failed to delete candidate from queue",
						"id", entry.ID,
						"ip", entry.IP,
						"port", entry.Port,
						"error", err,
					)
				}

				processed.Add(1)
			}
		}()
	}

	logger.Info("starting validation", "workers", workers, "batch_size", batchSize)

	var totalProcessed int
	for {
		if ctx.Err() != nil {
			break
		}

		entries, err := db.DequeueCandidates(batchSize)
		if err != nil {
			return fmt.Errorf("dequeueing candidates: %w", err)
		}

		if len(entries) == 0 {
			logger.Info("no more candidates in queue")
			break
		}

		total.Store(int64(totalProcessed + len(entries)))
		logger.Info("dequeued candidates", "count", len(entries), "batch_start", totalProcessed)
		totalProcessed += len(entries)

		for _, entry := range entries {
			select {
			case workerCh <- entry:
			case <-ctx.Done():
				for range workerCh {
				}
			}
		}
	}

	close(workerCh)

	// Wait for workers with a hard timeout so the process always exits.
	// Some proxy validations can hang on unresponsive targets; this ensures
	// we don't block indefinitely after the queue is empty.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	shutdownTimeout := time.Duration(timeout)*time.Second + 30*time.Second
	select {
	case <-done:
		// Workers finished cleanly
	case <-time.After(shutdownTimeout):
		logger.Warn("workers did not finish within timeout, forcing exit",
			"timeout", shutdownTimeout,
			"processed", processed.Load(),
			"verified", verified.Load(),
		)
	}

	totalVerified := int(verified.Load())
	status := "completed"
	if ctx.Err() != nil {
		status = "interrupted"
	}

	if err := db.FinishScanRun(startID, totalProcessed, totalVerified, status); err != nil {
		return fmt.Errorf("finishing scan run: %w", err)
	}

	logger.Info("validation complete",
		"status", status,
		"candidates", totalProcessed,
		"verified", totalVerified,
		"run_id", startID,
	)

	return nil
}

func resolveOriginIP(logger *slog.Logger, originIP string) (string, error) {
	if originIP != "" {
		return originIP, nil
	}

	logger.Info("ORIGIN_IP not set, auto-detecting egress IP...")

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

func envOrDefaultBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}
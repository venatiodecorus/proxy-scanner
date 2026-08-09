package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
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

const progressLogInterval = 15 * time.Minute

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
	skipAuxBlocklists := envOrDefaultBool("SKIP_AUX_BLOCKLISTS", false)
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
		"skip_aux_blocklists", skipAuxBlocklists,
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

	efnetChecker := blocklist.NewChecker(blocklist.WithLogger(logger))
	logger.Info("mandatory EFnet RBL eligibility checking enabled", "list", blocklist.EFnetList)

	var auxBLChecker *blocklist.Checker
	if !skipAuxBlocklists {
		auxBLChecker = blocklist.NewChecker(blocklist.WithLogger(logger))
		logger.Info("auxiliary blocklist checking enabled")
	} else {
		logger.Info("auxiliary blocklist checking disabled")
	}

	var verified atomic.Int64
	var processed atomic.Int64
	var efnetRejected atomic.Int64
	var efnetIndeterminate atomic.Int64
	var total atomic.Int64

	var deferred atomic.Int64
	deferCandidate := func(int64) {
		deferred.Add(1)
	}

	workerCh := make(chan proxy.CandidateEntry, workers*2)
	var wg sync.WaitGroup

	progressTicker := time.NewTicker(progressLogInterval)
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
					"efnet_rejected", efnetRejected.Load(),
					"efnet_indeterminate", efnetIndeterminate.Load(),
					"deferred", deferred.Load(),
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
				endpointEligibility := efnetChecker.CheckEFnet(ctx, candidate.IP)
				if endpointEligibility.Err != nil {
					efnetIndeterminate.Add(1)
					deferCandidate(entry.ID)
					logger.Warn("deferring candidate after indeterminate EFnet endpoint lookup",
						"id", entry.ID,
						"ip", candidate.IP,
						"port", candidate.Port,
						"error", endpointEligibility.Err,
					)
					processed.Add(1)
					continue
				}
				if endpointEligibility.Listed {
					efnetRejected.Add(1)
					logger.Info("rejecting EFnet-listed proxy endpoint",
						"ip", candidate.IP,
						"port", candidate.Port,
						"responses", endpointEligibility.Addresses,
					)
					if err := db.DeleteCandidate(entry.ID); err != nil {
						logger.Error("failed to delete EFnet-listed candidate", "id", entry.ID, "error", err)
					}
					processed.Add(1)
					continue
				}

				results := checker.Check(ctx, candidate)
				if ctx.Err() != nil {
					deferCandidate(entry.ID)
					processed.Add(1)
					continue
				}
				eligibilityCache := map[string]blocklist.LookupResult{
					candidate.IP: endpointEligibility,
				}
				candidateDeferred := false

				for _, result := range results {
					if ctx.Err() != nil {
						candidateDeferred = true
						break
					}
					if !result.Alive {
						continue
					}
					exitIP := net.ParseIP(result.ExitIP)
					if exitIP == nil || exitIP.To4() == nil {
						candidateDeferred = true
						efnetIndeterminate.Add(1)
						logger.Warn("deferring proxy result without an observable IPv4 exit",
							"ip", result.Candidate.IP,
							"port", result.Candidate.Port,
							"protocol", result.Protocol,
							"exit_ip", result.ExitIP,
						)
						continue
					}

					exitEligibility, ok := eligibilityCache[result.ExitIP]
					if !ok {
						exitEligibility = efnetChecker.CheckEFnet(ctx, result.ExitIP)
						eligibilityCache[result.ExitIP] = exitEligibility
					}
					if exitEligibility.Err != nil {
						candidateDeferred = true
						efnetIndeterminate.Add(1)
						logger.Warn("deferring candidate after indeterminate EFnet exit lookup",
							"id", entry.ID,
							"ip", result.Candidate.IP,
							"port", result.Candidate.Port,
							"protocol", result.Protocol,
							"exit_ip", result.ExitIP,
							"error", exitEligibility.Err,
						)
						continue
					}
					if exitEligibility.Listed {
						efnetRejected.Add(1)
						logger.Info("rejecting proxy with EFnet-listed exit",
							"ip", result.Candidate.IP,
							"port", result.Candidate.Port,
							"protocol", result.Protocol,
							"exit_ip", result.ExitIP,
							"responses", exitEligibility.Addresses,
						)
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

					if auxBLChecker != nil {
						blResult := auxBLChecker.Check(ctx, p.IP)
						if ctx.Err() != nil {
							candidateDeferred = true
							break
						}
						p.Blocklisted = blResult.Listed
						p.Blocklists = blResult.BlocklistsString()
						if p.Blocklisted {
							logger.Debug("proxy on auxiliary blocklist",
								"ip", p.IP,
								"port", p.Port,
								"blocklists", p.Blocklists,
							)
						}
					}

					if err := db.UpsertProxy(p); err != nil {
						candidateDeferred = true
						logger.Error("failed to upsert proxy; candidate will be retried",
							"ip", p.IP,
							"port", p.Port,
							"error", err,
						)
						continue
					}
					verified.Add(1)
				}

				if ctx.Err() != nil {
					candidateDeferred = true
				}
				if candidateDeferred {
					deferCandidate(entry.ID)
				} else if err := db.DeleteCandidate(entry.ID); err != nil {
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
				// Stop feeding workers; the close(workerCh) below will let
				// any active workers drain and exit. Don't try to drain
				// workerCh from this side — that's the workers' job.
				goto drained
			}
		}
	}
drained:

	close(workerCh)
	interrupted := ctx.Err() != nil

	// On normal completion, let in-flight workers finish their bounded network
	// operations. On signal-driven shutdown the signal handler has already
	// canceled ctx, so those operations still stop promptly.
	// Wait for workers with a hard timeout so the process always exits.
	// Some proxy validations can hang on unresponsive targets despite
	// per-check timeouts; the hard timeout below is the last line of defense.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	shutdownTimeout := time.Duration(timeout)*time.Second + 30*time.Second
	workersFinished := false
	select {
	case <-done:
		workersFinished = true
	case <-time.After(shutdownTimeout):
		logger.Warn("workers did not finish within timeout, forcing exit",
			"timeout", shutdownTimeout,
			"processed", processed.Load(),
			"verified", verified.Load(),
		)
	}

	if workersFinished {
		reset, err := db.ResetProcessingCandidates()
		if err != nil {
			logger.Error("failed to return retryable candidates to pending", "error", err)
		} else if reset > 0 {
			logger.Info("returned retryable candidates to pending", "count", reset)
		}
	}

	cancel()
	totalVerified := int(verified.Load())
	status := "completed"
	if interrupted || !workersFinished {
		status = "interrupted"
	}

	// Run cleanup with a bounded timeout. SQLite writes can block if the
	// scanner currently holds the single writer lock; we don't want that
	// to delay process exit.
	cleanupDone := make(chan struct{})
	go func() {
		if err := db.FinishScanRun(startID, totalProcessed, totalVerified, status); err != nil {
			logger.Error("failed to finish scan run", "error", err)
		}
		close(cleanupDone)
	}()
	select {
	case <-cleanupDone:
	case <-time.After(15 * time.Second):
		logger.Warn("cleanup (FinishScanRun) timed out, forcing exit")
	}

	logger.Info("validation complete",
		"status", status,
		"candidates", totalProcessed,
		"verified", totalVerified,
		"efnet_rejected", efnetRejected.Load(),
		"efnet_indeterminate", efnetIndeterminate.Load(),
		"deferred", deferred.Load(),
		"run_id", startID,
		"workers_finished_cleanly", workersFinished,
	)

	// If workers were stuck, they may still be holding goroutines. Force exit
	// rather than relying on main() to return (defers may also hang).
	if !workersFinished {
		os.Exit(1)
	}
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

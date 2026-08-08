// Command revalidator is a long-running service that periodically re-checks
// proxies in the database to keep the live set fresh. It complements the
// candidate validator by handling the inevitable churn after initial validation:
// proxies go offline, become slow, or change behavior.
//
// Loop:
//  1. Pick the N proxies with the oldest last_checked_at (NULLs first).
//  2. Re-run the full proxy check. On success, update volatile fields and
//     reset failure counters. On failure, increment consecutive_failures and
//     mark stale once the threshold is hit.
//  3. Periodically evict proxies that have failed enough consecutive checks
//     and whose last successful check is older than the grace period.
//  4. Sleep when nothing is due.
//
// Designed to run in parallel with the scanner/validator. Writes go through
// the same SQLite DB; WAL mode + busy_timeout handles serialization.
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

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("revalidator failed", "error", err)
		os.Exit(1)
	}
}

type config struct {
	dbPath            string
	geoipCityDB       string
	geoipASNDB        string
	workers           int
	timeout           time.Duration
	testURL           string
	originIP          string
	skipAuxBlocklists bool
	batchSize         int
	recheckInterval   time.Duration
	idleSleep         time.Duration
	failureThreshold  int
	evictAfter        time.Duration
	evictInterval     time.Duration
}

func loadConfig() config {
	return config{
		dbPath:            envOrDefault("DB_PATH", "/data/proxies.db"),
		geoipCityDB:       envOrDefault("GEOIP_CITY_DB", "/geoip/GeoLite2-City.mmdb"),
		geoipASNDB:        envOrDefault("GEOIP_ASN_DB", "/geoip/GeoLite2-ASN.mmdb"),
		workers:           envOrDefaultInt("WORKERS", 100),
		timeout:           time.Duration(envOrDefaultInt("TIMEOUT", 10)) * time.Second,
		testURL:           envOrDefault("TEST_URL", "http://httpbin.org/ip"),
		originIP:          envOrDefault("ORIGIN_IP", ""),
		skipAuxBlocklists: envOrDefaultBool("SKIP_AUX_BLOCKLISTS", false),
		batchSize:         envOrDefaultInt("BATCH_SIZE", 500),
		recheckInterval:   envOrDefaultDuration("RECHECK_INTERVAL", time.Hour),
		idleSleep:         envOrDefaultDuration("IDLE_SLEEP", time.Minute),
		failureThreshold:  envOrDefaultInt("FAILURE_THRESHOLD", 3),
		evictAfter:        envOrDefaultDuration("EVICT_AFTER", 7*24*time.Hour),
		evictInterval:     envOrDefaultDuration("EVICT_INTERVAL", time.Hour),
	}
}

func run(logger *slog.Logger) error {
	cfg := loadConfig()

	originIP, err := resolveOriginIP(logger, cfg.originIP)
	if err != nil && originIP == "" {
		logger.Warn("failed to auto-detect egress IP, anonymity detection will be limited", "error", err)
	}
	cfg.originIP = originIP

	logger.Info("starting revalidator",
		"db_path", cfg.dbPath,
		"workers", cfg.workers,
		"timeout", cfg.timeout,
		"test_url", cfg.testURL,
		"origin_ip", cfg.originIP,
		"skip_aux_blocklists", cfg.skipAuxBlocklists,
		"batch_size", cfg.batchSize,
		"recheck_interval", cfg.recheckInterval,
		"idle_sleep", cfg.idleSleep,
		"failure_threshold", cfg.failureThreshold,
		"evict_after", cfg.evictAfter,
		"evict_interval", cfg.evictInterval,
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

	db, err := database.Open(cfg.dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	geoip, err := proxy.NewGeoIPLookup(proxy.GeoIPConfig{
		CityDBPath: cfg.geoipCityDB,
		ASNDBPath:  cfg.geoipASNDB,
	})
	if err != nil {
		logger.Warn("geoip databases not available, skipping geo tagging", "error", err)
	}
	if geoip != nil {
		defer geoip.Close()
		logger.Info("geoip databases loaded")
	}

	checker := proxy.NewChecker(proxy.CheckerConfig{
		Timeout:  cfg.timeout,
		TestURL:  cfg.testURL,
		OriginIP: cfg.originIP,
		Logger:   logger,
	})

	efnetChecker := blocklist.NewChecker(blocklist.WithLogger(logger))
	logger.Info("mandatory EFnet RBL eligibility checking enabled", "list", blocklist.EFnetList)

	var auxBLChecker *blocklist.Checker
	if !cfg.skipAuxBlocklists {
		auxBLChecker = blocklist.NewChecker(blocklist.WithLogger(logger))
		logger.Info("auxiliary blocklist checking enabled")
	} else {
		logger.Info("auxiliary blocklist checking disabled")
	}

	r := &revalidator{
		cfg:          cfg,
		db:           db,
		checker:      checker,
		geoip:        geoip,
		efnetChecker: efnetChecker,
		auxBLChecker: auxBLChecker,
		logger:       logger,
	}

	// Eviction sweep runs on its own goroutine independent of the recheck loop
	// so a slow sweep can't starve rechecks (or vice versa).
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.evictionLoop(ctx)
	}()

	r.recheckLoop(ctx)

	cancel()
	wg.Wait()
	logger.Info("revalidator stopped")
	return nil
}

type revalidator struct {
	cfg          config
	db           *database.DB
	checker      *proxy.Checker
	geoip        *proxy.GeoIPLookup
	efnetChecker *blocklist.Checker
	auxBLChecker *blocklist.Checker
	logger       *slog.Logger
}

func (r *revalidator) recheckLoop(ctx context.Context) {
	var totalChecked, totalSuccess, totalFailed atomic.Int64

	progressTicker := time.NewTicker(60 * time.Second)
	defer progressTicker.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-progressTicker.C:
				r.logger.Info("revalidator progress",
					"checked", totalChecked.Load(),
					"success", totalSuccess.Load(),
					"failed", totalFailed.Load(),
				)
			}
		}
	}()

	for {
		if ctx.Err() != nil {
			return
		}

		batch, err := r.db.ListProxiesForRecheck(r.cfg.batchSize, r.cfg.recheckInterval)
		if err != nil {
			r.logger.Error("listing proxies for recheck", "error", err)
			if !sleepOrCancel(ctx, r.cfg.idleSleep) {
				return
			}
			continue
		}

		if len(batch) == 0 {
			r.logger.Debug("no proxies due for recheck", "sleep", r.cfg.idleSleep)
			if !sleepOrCancel(ctx, r.cfg.idleSleep) {
				return
			}
			continue
		}

		r.logger.Info("rechecking batch", "count", len(batch))
		r.processBatch(ctx, batch, &totalChecked, &totalSuccess, &totalFailed)
	}
}

func (r *revalidator) processBatch(
	ctx context.Context,
	batch []proxy.Proxy,
	totalChecked, totalSuccess, totalFailed *atomic.Int64,
) {
	workerCh := make(chan proxy.Proxy, r.cfg.workers*2)
	var wg sync.WaitGroup

	for i := 0; i < r.cfg.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range workerCh {
				if ctx.Err() != nil {
					return
				}
				ok := r.checkOne(ctx, p)
				totalChecked.Add(1)
				if ok {
					totalSuccess.Add(1)
				} else {
					totalFailed.Add(1)
				}
			}
		}()
	}

	for _, p := range batch {
		select {
		case workerCh <- p:
		case <-ctx.Done():
			close(workerCh)
			wg.Wait()
			return
		}
	}
	close(workerCh)
	wg.Wait()
}

// checkOne re-runs exactly the row's stored SOCKS protocol and records the
// outcome. Endpoint and observed-exit EFnet eligibility must both be
// conclusively clean before the row can remain active.
func (r *revalidator) checkOne(ctx context.Context, p proxy.Proxy) bool {
	endpointEligibility := r.efnetChecker.CheckEFnet(ctx, p.IP)
	if ctx.Err() != nil {
		return false
	}
	if endpointEligibility.Err != nil || endpointEligibility.Listed {
		return r.recordEligibilityFailure(p, "endpoint", p.IP, endpointEligibility)
	}

	match := r.checker.CheckProtocol(ctx, proxy.Candidate{IP: p.IP, Port: p.Port}, p.Protocol)
	if ctx.Err() != nil {
		return false
	}
	if match == nil || !match.Alive {
		if err := r.db.RecordCheckFailure(p.ID, r.cfg.failureThreshold); err != nil {
			r.logger.Error("record failure", "id", p.ID, "ip", p.IP, "port", p.Port, "error", err)
		}
		return false
	}

	exitIP := net.ParseIP(match.ExitIP)
	if exitIP == nil || exitIP.To4() == nil {
		return r.recordEligibilityFailure(p, "exit", match.ExitIP, blocklist.LookupResult{
			List: blocklist.EFnetList,
			Err:  fmt.Errorf("proxy did not expose an IPv4 exit address"),
		})
	}
	if match.ExitIP != p.IP {
		exitEligibility := r.efnetChecker.CheckEFnet(ctx, match.ExitIP)
		if ctx.Err() != nil {
			return false
		}
		if exitEligibility.Err != nil || exitEligibility.Listed {
			return r.recordEligibilityFailure(p, "exit", match.ExitIP, exitEligibility)
		}
	}

	update := database.CheckSuccessUpdate{
		LatencyMs:       match.LatencyMs,
		Anonymity:       match.Anonymity,
		ExitIP:          match.ExitIP,
		SupportsConnect: match.SupportsConnect,
		TLSInsecure:     match.TLSInsecure,
		// A prior EFnet rejection must be cleared once the mandatory lookup is
		// conclusively clean. If auxiliary checks are disabled, preserve any
		// unrelated auxiliary metadata instead of clearing it implicitly.
		SetBlocklist: p.Blocklists == blocklist.EFnetList,
	}

	if r.auxBLChecker != nil {
		blResult := r.auxBLChecker.Check(ctx, p.IP)
		if ctx.Err() != nil {
			return false
		}
		update.SetBlocklist = true
		update.Blocklisted = blResult.Listed
		update.Blocklists = blResult.BlocklistsString()
	}

	if err := r.db.RecordCheckSuccess(p.ID, update); err != nil {
		r.logger.Error("record success", "id", p.ID, "ip", p.IP, "port", p.Port, "error", err)
		return false
	}

	return true
}

func (r *revalidator) recordEligibilityFailure(p proxy.Proxy, scope, checkedIP string, result blocklist.LookupResult) bool {
	blocklisted := p.Blocklisted
	blocklists := p.Blocklists
	if result.Listed {
		blocklisted = true
		blocklists = blocklist.EFnetList
		r.logger.Info("marking proxy stale after EFnet RBL hit",
			"id", p.ID,
			"ip", p.IP,
			"port", p.Port,
			"protocol", p.Protocol,
			"scope", scope,
			"checked_ip", checkedIP,
			"responses", result.Addresses,
		)
	} else {
		r.logger.Warn("marking proxy stale after indeterminate EFnet RBL lookup",
			"id", p.ID,
			"ip", p.IP,
			"port", p.Port,
			"protocol", p.Protocol,
			"scope", scope,
			"checked_ip", checkedIP,
			"error", result.Err,
		)
	}

	if err := r.db.RecordEligibilityFailure(p.ID, blocklisted, blocklists); err != nil {
		r.logger.Error("record eligibility failure", "id", p.ID, "ip", p.IP, "port", p.Port, "error", err)
	}
	return false
}

func (r *revalidator) evictionLoop(ctx context.Context) {
	// Run once at startup so a fresh deployment can clean up immediately.
	r.evictOnce(ctx)

	ticker := time.NewTicker(r.cfg.evictInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.evictOnce(ctx)
		}
	}
}

func (r *revalidator) evictOnce(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	deleted, err := r.db.EvictDeadProxies(r.cfg.failureThreshold, r.cfg.evictAfter)
	if err != nil {
		r.logger.Error("evicting dead proxies", "error", err)
		return
	}
	if deleted > 0 {
		r.logger.Info("evicted dead proxies",
			"deleted", deleted,
			"failure_threshold", r.cfg.failureThreshold,
			"evict_after", r.cfg.evictAfter,
		)
	}
}

// sleepOrCancel sleeps for d or returns false if ctx is canceled first.
func sleepOrCancel(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
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

func envOrDefaultDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

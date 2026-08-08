package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/venatiodecorus/proxy-scanner/internal/database"
	"github.com/venatiodecorus/proxy-scanner/internal/proxy"
	"github.com/venatiodecorus/proxy-scanner/internal/scanner"
)

const progressLogInterval = 15 * time.Minute

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("scanner failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	scanRate := envOrDefaultInt("SCAN_RATE", 50000)
	scanPorts := envOrDefault("SCAN_PORTS", "1080,1081,9050")
	scanAdapter := envOrDefault("SCAN_ADAPTER", "ens3")
	excludeFile := envOrDefault("EXCLUDE_FILE", "/config/exclude.conf")
	dbPath := envOrDefault("DB_PATH", "/data/proxies.db")
	outputFile := envOrDefault("OUTPUT_FILE", "/data/candidates.json")
	resumeFile := envOrDefault("RESUME_FILE", "/data/paused.conf")
	scanTimeout := envOrDefaultDuration("SCAN_TIMEOUT", 0)

	logger.Info("starting proxy scanner",
		"scan_rate", scanRate,
		"scan_ports", scanPorts,
		"scan_adapter", scanAdapter,
		"exclude_file", excludeFile,
		"db_path", dbPath,
		"output_file", outputFile,
		"resume_file", resumeFile,
		"scan_timeout", scanTimeout,
	)

	db, err := database.Open(dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	masscanArgs := []string{
		"0.0.0.0/0",
		"-p" + scanPorts,
		"--excludefile", excludeFile,
		"--rate", strconv.Itoa(scanRate),
		"--adapter", scanAdapter,
		"--open",
		"-oJ", outputFile,
		"--source-port", "40000-56383",
	}

	resuming := false
	if _, err := os.Stat(resumeFile); err == nil {
		logger.Info("found resume file, continuing previous scan", "file", resumeFile)
		masscanArgs = append([]string{"--resume", resumeFile}, masscanArgs...)
		resuming = true
	}

	cmd := exec.Command("masscan", masscanArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = "/data"

	// Capture the pre-run mtime of the output file so we can detect whether
	// masscan produced any new output in this run. This lets us skip parsing
	// stale output from a prior run if masscan fails immediately (e.g. on a
	// failed --resume).
	var preRunMtime time.Time
	if st, err := os.Stat(outputFile); err == nil {
		preRunMtime = st.ModTime()
	}

	logger.Info("running masscan",
		"started", time.Now().UTC().Format(time.RFC3339),
		"resuming", resuming,
		"timeout", scanTimeout,
	)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting masscan: %w", err)
	}

	stopProgress := startScannerProgress(logger, db, outputFile, time.Now())
	defer stopProgress()

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	var timeoutCh <-chan time.Time
	if scanTimeout > 0 {
		timeoutCh = time.After(scanTimeout)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case err := <-done:
		if err != nil {
			if resuming {
				logger.Warn("masscan exited with error after resume; resume file preserved for next attempt", "error", err)
				// If masscan failed immediately on resume without producing new
				// output, skip parsing to avoid re-enqueueing stale candidates
				// from a prior run's output file.
				if !outputFileIsFresh(outputFile, preRunMtime) {
					logger.Info("resume failed with no new scan output; skipping parse")
					return nil
				}
				return parseAndEnqueue(logger, db, outputFile)
			}
			return fmt.Errorf("masscan failed: %w", err)
		}
		logger.Info("masscan completed naturally")

	case <-timeoutCh:
		logger.Info("scan timeout reached, sending SIGINT to masscan", "timeout", scanTimeout)
		if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
			logger.Warn("failed to send SIGINT, killing process", "error", err)
			cmd.Process.Kill()
		}
		err := <-done
		if err != nil {
			logger.Info("masscan exited after timeout", "error", err)
		}

	case sig := <-sigCh:
		logger.Info("received signal, forwarding to masscan", "signal", sig)
		if err := cmd.Process.Signal(sig); err != nil {
			cmd.Process.Kill()
		}
		<-done
		return fmt.Errorf("scanner interrupted by signal: %v", sig)
	}

	if _, err := os.Stat(resumeFile); err == nil {
		logger.Info("scan state saved for next resume", "file", resumeFile)
	} else if scanTimeout > 0 {
		if _, err := os.Stat("/data/paused.conf"); err == nil {
			logger.Warn("masscan wrote paused.conf but to unexpected path; check /data/paused.conf")
		}
	}

	return parseAndEnqueue(logger, db, outputFile)
}

// startScannerProgress logs approximate masscan output and queue totals at a
// low frequency while the scanner process is running.
func startScannerProgress(logger *slog.Logger, db *database.DB, outputFile string, started time.Time) func() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		ticker := time.NewTicker(progressLogInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				records, size, err := scanOutputTotals(outputFile)
				if err != nil {
					logger.Warn("failed to read scan progress", "file", outputFile, "error", err)
					continue
				}
				pending, err := db.PendingCandidateCount()
				if err != nil {
					logger.Warn("failed to read pending candidate total", "error", err)
				}
				logger.Info("scanner progress",
					"elapsed", time.Since(started).Round(time.Second),
					"masscan_records", records,
					"output_bytes", size,
					"pending_in_queue", pending,
				)
			}
		}
	}()

	return func() {
		cancel()
		<-done
	}
}

func scanOutputTotals(outputFile string) (records int64, size int64, err error) {
	f, err := os.Open(outputFile)
	if os.IsNotExist(err) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, fmt.Errorf("opening output file: %w", err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return 0, 0, fmt.Errorf("stating output file: %w", err)
	}

	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	for s.Scan() {
		if bytes.Contains(s.Bytes(), []byte(`"ip"`)) {
			records++
		}
	}
	if err := s.Err(); err != nil {
		return 0, st.Size(), fmt.Errorf("counting output records: %w", err)
	}
	return records, st.Size(), nil
}

// outputFileIsFresh reports whether outputFile has been modified since
// preRunMtime. A zero preRunMtime means the file did not exist before the
// run, so any existing file now is considered fresh.
func outputFileIsFresh(outputFile string, preRunMtime time.Time) bool {
	st, err := os.Stat(outputFile)
	if err != nil {
		return false
	}
	if preRunMtime.IsZero() {
		return true
	}
	return st.ModTime().After(preRunMtime)
}

func parseAndEnqueue(logger *slog.Logger, db *database.DB, outputFile string) error {
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		logger.Info("no output file, nothing to enqueue")
		return nil
	}

	logger.Info("parsing scan results", "file", outputFile)

	candidateStream, countCh, parseErrCh := scanner.ParseFileStream(outputFile, logger)

	var candidates []proxy.Candidate
	for c := range candidateStream {
		candidates = append(candidates, c)
	}

	totalCandidates := <-countCh
	if parseErr := <-parseErrCh; parseErr != nil {
		return fmt.Errorf("parsing scan results: %w", parseErr)
	}

	logger.Info("parsed candidates", "count", totalCandidates, "unique", len(candidates))

	if len(candidates) == 0 {
		logger.Info("no candidates found in output")
		return nil
	}

	enqueued, err := db.EnqueueCandidates(candidates)
	if err != nil {
		return fmt.Errorf("enqueueing candidates: %w", err)
	}

	pending, err := db.PendingCandidateCount()
	if err != nil {
		logger.Warn("failed to get pending count", "error", err)
	}

	logger.Info("candidates enqueued",
		"new", enqueued,
		"total_candidates", totalCandidates,
		"unique_candidates", len(candidates),
		"duplicates_skipped", int64(len(candidates))-enqueued,
		"pending_in_queue", pending,
	)

	return nil
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

func envOrDefaultDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		slog.Warn("invalid duration, using default", "key", key, "value", v, "error", err)
		return def
	}
	return d
}

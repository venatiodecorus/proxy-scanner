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
	scanPorts := envOrDefault("SCAN_PORTS", "1080,1081,4145,9050")
	// Empty means "let masscan pick the default-route interface". There is
	// deliberately no default here: hardcoding an interface name (it used to be
	// the OpenStack-specific "ens3") makes the scanner fail on any host that
	// names its NIC differently.
	scanAdapter := os.Getenv("SCAN_ADAPTER")
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

	// Fail closed: we scan 0.0.0.0/0, so an incomplete or missing exclusion list
	// means scanning military, government and infrastructure networks. Validate
	// before masscan gets a chance to send a single packet.
	if err := validateExcludeFile(excludeFile, logger); err != nil {
		return fmt.Errorf("exclude file preflight failed: %w", err)
	}

	db, err := database.Open(dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	// Resolve resume state *before* building the argument list. On a resume the
	// target ranges come out of paused.conf and must not also be given on the
	// command line — see buildMasscanArgs.
	resumeArg := ""
	if _, err := os.Stat(resumeFile); err == nil {
		logger.Info("found resume file, continuing previous scan", "file", resumeFile)
		resumeArg = resumeFile
	}
	resuming := resumeArg != ""

	masscanArgs := buildMasscanArgs(masscanConfig{
		ports:       scanPorts,
		excludeFile: excludeFile,
		rate:        scanRate,
		adapter:     scanAdapter,
		outputFile:  outputFile,
		resumeFile:  resumeArg,
	})

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

		// The sweep finished, so there is nothing left to resume. masscan writes
		// paused.conf only when it is interrupted and never clears a stale one, so
		// leaving the previous session's file behind would make the next session
		// resume an already-finished sweep — rescanning its final chunk forever
		// instead of starting a new pass over the address space.
		if err := os.Remove(resumeFile); err == nil {
			logger.Info("sweep complete, cleared resume state; next session starts a fresh pass",
				"file", resumeFile)
		} else if !os.IsNotExist(err) {
			logger.Warn("failed to clear resume file after a completed sweep",
				"file", resumeFile, "error", err)
		}

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

// masscanConfig is the set of knobs that shape the masscan command line.
type masscanConfig struct {
	ports       string
	excludeFile string
	rate        int
	adapter     string
	outputFile  string
	// resumeFile, when set, makes this a resumed session: masscan reads the
	// unscanned remainder from that file instead of being given a target.
	resumeFile string
}

// buildMasscanArgs assembles the masscan invocation.
//
// Target selection is the subtle part. masscan treats target ranges as
// ADDITIVE — every range on the command line is unioned into the set. This
// build of masscan records its progress in paused.conf as the list of *remaining*
// ranges (there is no resume-index), so passing "0.0.0.0/0" alongside --resume
// unions the whole address space back in and silently discards everything the
// previous sessions covered. Every session then rescans the same opening slice
// and the sweep never advances.
//
// So: exactly one of --resume or a bare target, never both.
//
// --excludefile is always present, on both paths. masscan does not persist
// excludes into paused.conf (upstream issue #110) and refuses a large scan
// without at least one exclude, so it has to be re-specified on a resume — and
// it is what keeps the resumed range set safe. The exclusion list is validated
// separately by validateExcludeFile before we get here.
//
// The remaining flags are scalars (--rate, -oJ, --adapter) or an identical set
// (-p), so re-specifying them on a resume is harmless; only the range list
// accumulates.
//
// adapter is optional: when empty, the flag is omitted entirely and masscan
// picks the default-route interface itself. Passing a wrong interface name is a
// hard failure, so "unset" has to mean "auto-detect" rather than some guess
// baked into the binary.
func buildMasscanArgs(cfg masscanConfig) []string {
	var args []string
	if cfg.resumeFile != "" {
		args = append(args, "--resume", cfg.resumeFile)
	} else {
		args = append(args, "0.0.0.0/0")
	}

	args = append(args,
		"-p"+cfg.ports,
		"--excludefile", cfg.excludeFile,
		"--rate", strconv.Itoa(cfg.rate),
		"--open",
		"-oJ", cfg.outputFile,
		"--source-port", "40000-56383",
	)
	if cfg.adapter != "" {
		args = append(args, "--adapter", cfg.adapter)
	}
	return args
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

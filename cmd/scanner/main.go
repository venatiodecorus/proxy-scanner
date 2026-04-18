package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
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
		logger.Error("scanner failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	scanRate := envOrDefaultInt("SCAN_RATE", 50000)
	scanPorts := envOrDefault("SCAN_PORTS", "3128,8080,1080,8888,9050,8443,3129,80,443,1081")
	scanAdapter := envOrDefault("SCAN_ADAPTER", "ens3")
	excludeFile := envOrDefault("EXCLUDE_FILE", "/config/exclude.conf")
	dbPath := envOrDefault("DB_PATH", "/data/proxies.db")
	outputFile := envOrDefault("OUTPUT_FILE", "/data/candidates.json")

	logger.Info("starting proxy scanner",
		"scan_rate", scanRate,
		"scan_ports", scanPorts,
		"scan_adapter", scanAdapter,
		"exclude_file", excludeFile,
		"db_path", dbPath,
		"output_file", outputFile,
	)

	db, err := database.Open(dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	logger.Info("running masscan", "started", time.Now().UTC().Format(time.RFC3339))

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

	cmd := exec.Command("masscan", masscanArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running masscan: %w", err)
	}

	logger.Info("masscan complete, parsing results", "file", outputFile)

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
		logger.Info("no candidates found, exiting")
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
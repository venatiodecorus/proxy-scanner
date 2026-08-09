package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// writeExclude writes an exclusion file containing every canary network plus
// enough filler /32s to clear minExcludeEntries, then applies the given edits.
func writeExclude(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "exclude.conf")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// canaryLines renders the canary table as /32 exclusions, so a valid baseline
// file can be built without hardcoding the canary addresses twice.
func canaryLines() []string {
	var lines []string
	for _, c := range excludeCanaries {
		lines = append(lines, c.ip+"/32")
	}
	return lines
}

func fillerLines(n int) []string {
	lines := make([]string, 0, n)
	// 203.0.113.0/24 is RFC 5737 documentation space; safe filler that will
	// never collide with a canary.
	for i := 0; i < n; i++ {
		lines = append(lines, "203.0.113.0/24")
	}
	return lines
}

func TestValidateExcludeFileAcceptsCompleteList(t *testing.T) {
	lines := append(canaryLines(), fillerLines(minExcludeEntries)...)
	path := writeExclude(t, lines)

	if err := validateExcludeFile(path, discardLogger()); err != nil {
		t.Fatalf("expected complete exclude file to validate, got: %v", err)
	}
}

func TestValidateExcludeFileRejectsMissingFile(t *testing.T) {
	err := validateExcludeFile(filepath.Join(t.TempDir(), "nope.conf"), discardLogger())
	if err == nil {
		t.Fatal("expected a missing exclude file to abort the scan")
	}
}

func TestValidateExcludeFileRejectsEmptyFile(t *testing.T) {
	path := writeExclude(t, []string{"# only a comment", ""})
	err := validateExcludeFile(path, discardLogger())
	if err == nil {
		t.Fatal("expected an empty exclude file to abort the scan")
	}
	if !strings.Contains(err.Error(), "expected at least") {
		t.Fatalf("expected an entry-count error, got: %v", err)
	}
}

func TestValidateExcludeFileRejectsTruncatedList(t *testing.T) {
	// Every canary present, but far too few entries overall — the signature of a
	// build-time merge that only picked up some fragments.
	path := writeExclude(t, canaryLines())
	err := validateExcludeFile(path, discardLogger())
	if err == nil {
		t.Fatal("expected a short exclude file to abort the scan")
	}
	if !strings.Contains(err.Error(), "expected at least") {
		t.Fatalf("expected an entry-count error, got: %v", err)
	}
}

func TestValidateExcludeFileRejectsMissingCanary(t *testing.T) {
	// Drop the military ASN canary specifically: this is the case where
	// 11-military-asn.conf failed to merge but everything else is fine.
	var lines []string
	for _, c := range excludeCanaries {
		if c.ip == "128.25.4.5" {
			continue
		}
		lines = append(lines, c.ip+"/32")
	}
	lines = append(lines, fillerLines(minExcludeEntries)...)
	path := writeExclude(t, lines)

	err := validateExcludeFile(path, discardLogger())
	if err == nil {
		t.Fatal("expected a missing canary to abort the scan")
	}
	if !strings.Contains(err.Error(), "128.25.4.5") {
		t.Fatalf("expected the error to name the uncovered canary, got: %v", err)
	}
}

func TestValidateExcludeFileRejectsMalformedEntry(t *testing.T) {
	lines := append(canaryLines(), fillerLines(minExcludeEntries)...)
	lines = append(lines, "not-a-cidr")
	path := writeExclude(t, lines)

	err := validateExcludeFile(path, discardLogger())
	if err == nil {
		t.Fatal("expected a malformed entry to abort the scan")
	}
	if !strings.Contains(err.Error(), "unparseable") {
		t.Fatalf("expected an unparseable-entry error, got: %v", err)
	}
}

func TestParseExcludeFileHandlesCommentsAndBareIPs(t *testing.T) {
	path := writeExclude(t, []string{
		"# a comment",
		"",
		"   ",
		"10.0.0.0/8   # trailing comment",
		"1.2.3.4",
		"\t192.168.0.0/16",
	})

	nets, malformed, err := parseExcludeFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(malformed) != 0 {
		t.Fatalf("expected no malformed entries, got %v", malformed)
	}
	if len(nets) != 3 {
		t.Fatalf("expected 3 networks, got %d: %v", len(nets), nets)
	}
	if got := nets[1].String(); got != "1.2.3.4/32" {
		t.Fatalf("expected bare IP to normalise to /32, got %s", got)
	}
}

// TestCommittedExcludeListPassesPreflight validates the real files in
// config/exclude/ the same way the scanner will at runtime. This is the test
// that fails if someone edits or regenerates the lists into an unsafe state.
func TestCommittedExcludeListPassesPreflight(t *testing.T) {
	fragments, err := filepath.Glob(filepath.Join("..", "..", "config", "exclude", "*.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fragments) == 0 {
		t.Fatal("no exclusion fragments found under config/exclude/")
	}

	// Mirror the Dockerfile's build-time merge: plain concatenation.
	var merged strings.Builder
	for _, frag := range fragments {
		b, err := os.ReadFile(frag)
		if err != nil {
			t.Fatal(err)
		}
		merged.Write(b)
		merged.WriteString("\n")
	}

	path := filepath.Join(t.TempDir(), "exclude.conf")
	if err := os.WriteFile(path, []byte(merged.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := validateExcludeFile(path, discardLogger()); err != nil {
		t.Fatalf("committed exclusion lists fail the scanner preflight: %v", err)
	}
}

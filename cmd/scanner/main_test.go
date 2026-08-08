package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanOutputTotals(t *testing.T) {
	content := "[\n" +
		`{"ip":"1.2.3.4","ports":[{"port":1080}]},` + "\n" +
		`{"ip":"5.6.7.8","ports":[{"port":9050}]}` + "\n]"
	path := filepath.Join(t.TempDir(), "candidates.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	records, size, err := scanOutputTotals(path)
	if err != nil {
		t.Fatalf("scanOutputTotals returned error: %v", err)
	}
	if records != 2 {
		t.Fatalf("expected 2 records, got %d", records)
	}
	if size != int64(len(content)) {
		t.Fatalf("expected size %d, got %d", len(content), size)
	}
}

func TestScanOutputTotalsMissingFile(t *testing.T) {
	records, size, err := scanOutputTotals(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatalf("missing output should not fail: %v", err)
	}
	if records != 0 || size != 0 {
		t.Fatalf("expected zero totals, got records=%d size=%d", records, size)
	}
}

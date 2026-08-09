package main

import (
	"os"
	"path/filepath"
	"strings"
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

func TestBuildMasscanArgsOmitsAdapterWhenUnset(t *testing.T) {
	args := buildMasscanArgs(masscanConfig{
		ports:       "1080,1081,9050",
		excludeFile: "/config/exclude.conf",
		rate:        50000,
		adapter:     "",
		outputFile:  "/data/candidates.json",
	})

	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--adapter") {
		t.Fatalf("expected --adapter to be omitted when unset, got: %s", joined)
	}
	// Hardcoding an interface name is what broke the move off OpenStack.
	if strings.Contains(joined, "ens3") {
		t.Fatalf("no interface name should be baked in, got: %s", joined)
	}
}

func TestBuildMasscanArgsIncludesAdapterWhenSet(t *testing.T) {
	args := buildMasscanArgs(masscanConfig{
		ports: "1080", excludeFile: "/config/exclude.conf", rate: 1000,
		adapter: "eth0", outputFile: "/data/candidates.json",
	})

	found := false
	for i, a := range args {
		if a == "--adapter" {
			if i+1 >= len(args) || args[i+1] != "eth0" {
				t.Fatalf("--adapter not followed by its value: %v", args)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("expected --adapter eth0, got: %v", args)
	}
}

// The target and the exclusion file are the safety contract: masscan must never
// be invoked against 0.0.0.0/0 without --excludefile.
func TestBuildMasscanArgsAlwaysExcludes(t *testing.T) {
	for _, adapter := range []string{"", "eth0"} {
		args := buildMasscanArgs(masscanConfig{
			ports: "1080", excludeFile: "/config/exclude.conf", rate: 1000,
			adapter: adapter, outputFile: "/data/candidates.json",
		})
		if args[0] != "0.0.0.0/0" {
			t.Errorf("adapter=%q: expected 0.0.0.0/0 as the target, got %q", adapter, args[0])
		}
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "--excludefile /config/exclude.conf") {
			t.Errorf("adapter=%q: --excludefile missing from %s", adapter, joined)
		}
	}
}

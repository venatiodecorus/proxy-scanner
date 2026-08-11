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
		ports:       "1080,1081,4145,9050",
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

// --excludefile is the safety contract and must be present on every path,
// including a resume: masscan does not persist excludes into paused.conf.
func TestBuildMasscanArgsAlwaysExcludes(t *testing.T) {
	for _, adapter := range []string{"", "eth0"} {
		for _, resume := range []string{"", "/data/paused.conf"} {
			args := buildMasscanArgs(masscanConfig{
				ports: "1080", excludeFile: "/config/exclude.conf", rate: 1000,
				adapter: adapter, outputFile: "/data/candidates.json", resumeFile: resume,
			})
			joined := strings.Join(args, " ")
			if !strings.Contains(joined, "--excludefile /config/exclude.conf") {
				t.Errorf("adapter=%q resume=%q: --excludefile missing from %s", adapter, resume, joined)
			}
		}
	}
}

// A fresh scan targets the whole address space explicitly.
func TestBuildMasscanArgsFreshScanTargetsEverything(t *testing.T) {
	args := buildMasscanArgs(masscanConfig{
		ports: "1080", excludeFile: "/config/exclude.conf", rate: 1000,
		outputFile: "/data/candidates.json",
	})
	if args[0] != "0.0.0.0/0" {
		t.Fatalf("expected 0.0.0.0/0 as the target, got %q (%v)", args[0], args)
	}
	if strings.Contains(strings.Join(args, " "), "--resume") {
		t.Fatalf("a fresh scan must not pass --resume: %v", args)
	}
}

// The regression this guards is subtle and cost a wasted sweep: masscan unions
// every target range it is given, and this build stores progress in paused.conf
// as the list of *remaining* ranges. Passing a bare 0.0.0.0/0 alongside --resume
// therefore restores the already-scanned space and the sweep never advances.
func TestBuildMasscanArgsResumeOmitsTarget(t *testing.T) {
	args := buildMasscanArgs(masscanConfig{
		ports: "1080,1081,4145,9050", excludeFile: "/config/exclude.conf", rate: 50000,
		outputFile: "/data/candidates.json", resumeFile: "/data/paused.conf",
	})

	for _, a := range args {
		if a == "0.0.0.0/0" {
			t.Fatalf("resume must not re-specify a target range; it is unioned with "+
				"paused.conf's remainder and wipes scan progress: %v", args)
		}
	}
	if args[0] != "--resume" || args[1] != "/data/paused.conf" {
		t.Fatalf("expected --resume first, got %v", args)
	}
}

// Resume and a bare target are mutually exclusive: exactly one is always present.
func TestBuildMasscanArgsTargetIsExclusive(t *testing.T) {
	for _, resume := range []string{"", "/data/paused.conf"} {
		args := buildMasscanArgs(masscanConfig{
			ports: "1080", excludeFile: "/config/exclude.conf", rate: 1000,
			outputFile: "/data/candidates.json", resumeFile: resume,
		})
		joined := strings.Join(args, " ")
		hasTarget := strings.Contains(joined, "0.0.0.0/0")
		hasResume := strings.Contains(joined, "--resume")
		if hasTarget == hasResume {
			t.Errorf("resume=%q: expected exactly one of a target or --resume, got target=%v resume=%v in %v",
				resume, hasTarget, hasResume, args)
		}
	}
}

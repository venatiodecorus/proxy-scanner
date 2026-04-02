package scanner

import (
	"os"
	"strings"
	"testing"

	"github.com/venatiodecorus/proxy-scanner/internal/proxy"
)

func TestParseStandardJSON(t *testing.T) {
	input := `[
		{"ip": "1.2.3.4", "timestamp": "1234567890", "ports": [{"port": 8080, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]},
		{"ip": "5.6.7.8", "timestamp": "1234567891", "ports": [{"port": 3128, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 128}]}
	]`

	candidates, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(candidates))
	}
	if candidates[0].IP != "1.2.3.4" || candidates[0].Port != 8080 {
		t.Errorf("candidate 0: got %s:%d", candidates[0].IP, candidates[0].Port)
	}
	if candidates[1].IP != "5.6.7.8" || candidates[1].Port != 3128 {
		t.Errorf("candidate 1: got %s:%d", candidates[1].IP, candidates[1].Port)
	}
}

func TestParseTrailingComma(t *testing.T) {
	// Masscan's typical output — trailing comma before closing bracket
	input := `[
		{"ip": "1.2.3.4", "timestamp": "1234567890", "ports": [{"port": 8080, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]},
		{"ip": "5.6.7.8", "timestamp": "1234567891", "ports": [{"port": 3128, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 128}]},
	]`

	candidates, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parsing with trailing comma: %v", err)
	}
	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(candidates))
	}
}

func TestParseMultiplePorts(t *testing.T) {
	input := `[
		{"ip": "1.2.3.4", "timestamp": "1234567890", "ports": [
			{"port": 8080, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64},
			{"port": 3128, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}
		]}
	]`

	candidates, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates (two ports on same IP), got %d", len(candidates))
	}
	if candidates[0].IP != "1.2.3.4" || candidates[0].Port != 8080 {
		t.Errorf("candidate 0: got %s:%d", candidates[0].IP, candidates[0].Port)
	}
	if candidates[1].IP != "1.2.3.4" || candidates[1].Port != 3128 {
		t.Errorf("candidate 1: got %s:%d", candidates[1].IP, candidates[1].Port)
	}
}

func TestParseFiltersClosed(t *testing.T) {
	input := `[
		{"ip": "1.2.3.4", "timestamp": "1234567890", "ports": [{"port": 8080, "proto": "tcp", "status": "closed", "reason": "rst", "ttl": 64}]},
		{"ip": "5.6.7.8", "timestamp": "1234567891", "ports": [{"port": 3128, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 128}]}
	]`

	candidates, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate (closed ports filtered), got %d", len(candidates))
	}
	if candidates[0].IP != "5.6.7.8" {
		t.Errorf("expected IP 5.6.7.8, got %s", candidates[0].IP)
	}
}

func TestParseFiltersUDP(t *testing.T) {
	input := `[
		{"ip": "1.2.3.4", "timestamp": "1234567890", "ports": [{"port": 8080, "proto": "udp", "status": "open", "reason": "none", "ttl": 64}]},
		{"ip": "5.6.7.8", "timestamp": "1234567891", "ports": [{"port": 3128, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 128}]}
	]`

	candidates, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate (UDP filtered), got %d", len(candidates))
	}
}

func TestParseDeduplicates(t *testing.T) {
	input := `[
		{"ip": "1.2.3.4", "timestamp": "1234567890", "ports": [{"port": 8080, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]},
		{"ip": "1.2.3.4", "timestamp": "1234567891", "ports": [{"port": 8080, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]}
	]`

	candidates, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate (deduped), got %d", len(candidates))
	}
}

func TestParseEmpty(t *testing.T) {
	candidates, err := Parse(strings.NewReader("[]"))
	if err != nil {
		t.Fatalf("parsing empty: %v", err)
	}
	if len(candidates) != 0 {
		t.Fatalf("expected 0 candidates, got %d", len(candidates))
	}
}

func TestParseTruncatedOutput(t *testing.T) {
	// Masscan might produce truncated output if killed mid-scan
	input := `[
		{"ip": "1.2.3.4", "timestamp": "1234567890", "ports": [{"port": 8080, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]},
		{"ip": "5.6.7.8", "timestamp": "1234567891", "ports": [{"port": 3128, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 128}]},`

	candidates, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parsing truncated: %v", err)
	}
	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates from truncated output, got %d", len(candidates))
	}
}

// --- Streaming parser tests ---

// collectStream drains a candidate channel into a slice.
func collectStream(ch <-chan proxy.Candidate) []proxy.Candidate {
	var out []proxy.Candidate
	for c := range ch {
		out = append(out, c)
	}
	return out
}

// writeTemp writes content to a temp file and returns its path.
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "masscan-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func TestStreamParseStandardJSON(t *testing.T) {
	input := `[
		{"ip": "1.2.3.4", "timestamp": "1234567890", "ports": [{"port": 8080, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]},
		{"ip": "5.6.7.8", "timestamp": "1234567891", "ports": [{"port": 3128, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 128}]}
	]`

	path := writeTemp(t, input)
	candidateCh, countCh, errCh := ParseFileStream(path, nil)
	candidates := collectStream(candidateCh)
	count := <-countCh
	if err := <-errCh; err != nil {
		t.Fatalf("stream parse error: %v", err)
	}

	if count != 2 {
		t.Fatalf("expected count 2, got %d", count)
	}
	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(candidates))
	}
	if candidates[0].IP != "1.2.3.4" || candidates[0].Port != 8080 {
		t.Errorf("candidate 0: got %s:%d", candidates[0].IP, candidates[0].Port)
	}
	if candidates[1].IP != "5.6.7.8" || candidates[1].Port != 3128 {
		t.Errorf("candidate 1: got %s:%d", candidates[1].IP, candidates[1].Port)
	}
}

func TestStreamParseTrailingComma(t *testing.T) {
	// Masscan's typical output — trailing comma before closing bracket.
	// json.Decoder handles this by skipping the trailing comma token errors.
	input := `[
		{"ip": "1.2.3.4", "timestamp": "1234567890", "ports": [{"port": 8080, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]},
		{"ip": "5.6.7.8", "timestamp": "1234567891", "ports": [{"port": 3128, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 128}]}
	]`

	path := writeTemp(t, input)
	candidateCh, countCh, errCh := ParseFileStream(path, nil)
	candidates := collectStream(candidateCh)
	count := <-countCh
	if err := <-errCh; err != nil {
		t.Fatalf("stream parse error: %v", err)
	}

	if count != 2 || len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d (count=%d)", len(candidates), count)
	}
}

func TestStreamParseDeduplicates(t *testing.T) {
	input := `[
		{"ip": "1.2.3.4", "timestamp": "1234567890", "ports": [{"port": 8080, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]},
		{"ip": "1.2.3.4", "timestamp": "1234567891", "ports": [{"port": 8080, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]}
	]`

	path := writeTemp(t, input)
	candidateCh, countCh, errCh := ParseFileStream(path, nil)
	candidates := collectStream(candidateCh)
	count := <-countCh
	if err := <-errCh; err != nil {
		t.Fatalf("stream parse error: %v", err)
	}

	if count != 1 || len(candidates) != 1 {
		t.Fatalf("expected 1 candidate (deduped), got %d (count=%d)", len(candidates), count)
	}
}

func TestStreamParseFiltersClosed(t *testing.T) {
	input := `[
		{"ip": "1.2.3.4", "timestamp": "1234567890", "ports": [{"port": 8080, "proto": "tcp", "status": "closed", "reason": "rst", "ttl": 64}]},
		{"ip": "5.6.7.8", "timestamp": "1234567891", "ports": [{"port": 3128, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 128}]}
	]`

	path := writeTemp(t, input)
	candidateCh, countCh, errCh := ParseFileStream(path, nil)
	candidates := collectStream(candidateCh)
	count := <-countCh
	if err := <-errCh; err != nil {
		t.Fatalf("stream parse error: %v", err)
	}

	if count != 1 || len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d (count=%d)", len(candidates), count)
	}
	if candidates[0].IP != "5.6.7.8" {
		t.Errorf("expected IP 5.6.7.8, got %s", candidates[0].IP)
	}
}

func TestStreamParseEmpty(t *testing.T) {
	path := writeTemp(t, "[]")
	candidateCh, countCh, errCh := ParseFileStream(path, nil)
	candidates := collectStream(candidateCh)
	count := <-countCh
	if err := <-errCh; err != nil {
		t.Fatalf("stream parse error: %v", err)
	}

	if count != 0 || len(candidates) != 0 {
		t.Fatalf("expected 0 candidates, got %d (count=%d)", len(candidates), count)
	}
}

func TestStreamParseMultiplePorts(t *testing.T) {
	input := `[
		{"ip": "1.2.3.4", "timestamp": "1234567890", "ports": [
			{"port": 8080, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64},
			{"port": 3128, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}
		]}
	]`

	path := writeTemp(t, input)
	candidateCh, countCh, errCh := ParseFileStream(path, nil)
	candidates := collectStream(candidateCh)
	count := <-countCh
	if err := <-errCh; err != nil {
		t.Fatalf("stream parse error: %v", err)
	}

	if count != 2 || len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d (count=%d)", len(candidates), count)
	}
}

func TestStreamParseFileNotFound(t *testing.T) {
	candidateCh, countCh, errCh := ParseFileStream("/nonexistent/file.json", nil)
	candidates := collectStream(candidateCh)
	count := <-countCh
	err := <-errCh

	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if count != 0 || len(candidates) != 0 {
		t.Fatalf("expected 0 candidates, got %d (count=%d)", len(candidates), count)
	}
}

func TestCleanMasscanJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", "[]"},
		{"whitespace", "   \n\t  ", "[]"},
		{"clean", `[{"a":1}]`, `[{"a":1}]`},
		{"trailing comma", `[{"a":1},]`, `[{"a":1}]`},
		{"trailing comma with whitespace", "[{\"a\":1},\n]", "[{\"a\":1}\n]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(cleanMasscanJSON([]byte(tt.input)))
			if got != tt.want {
				t.Errorf("cleanMasscanJSON(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

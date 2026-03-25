package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/venatiodecorus/proxy-scanner/internal/proxy"
)

// masscanRecord represents a single entry in masscan's JSON output.
// Masscan JSON format (with -oJ flag):
//
//	[
//	  { "ip": "1.2.3.4", "timestamp": "1234567890", "ports": [ {"port": 8080, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ] },
//	  ...
//	]
//
// Note: masscan outputs a trailing comma after the last entry and a closing
// bracket, but the JSON is otherwise valid. We handle both strict and
// masscan's slightly malformed output.
type masscanRecord struct {
	IP    string        `json:"ip"`
	Ports []masscanPort `json:"ports"`
}

type masscanPort struct {
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Status string `json:"status"`
}

// ParseFile reads a masscan JSON output file and returns a slice of Candidates.
func ParseFile(path string) ([]proxy.Candidate, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening scan file: %w", err)
	}
	defer f.Close()

	return Parse(f)
}

// Parse reads masscan JSON output from a reader and returns candidates.
// It handles masscan's JSON quirks: the output may have trailing commas
// and the array may not be properly terminated.
func Parse(r io.Reader) ([]proxy.Candidate, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading scan data: %w", err)
	}

	// Masscan's JSON output has quirks:
	// - It may end with ",\n]" or just "]"
	// - It may have a trailing ",\n" before the closing bracket
	// We clean it up for the standard JSON parser.
	data = cleanMasscanJSON(data)

	var records []masscanRecord
	if err := json.Unmarshal(data, &records); err != nil {
		// If standard parsing fails, try line-by-line parsing
		// (masscan can also output one JSON object per line with -oJ)
		candidates, lineErr := parseLineByLine(data)
		if lineErr != nil {
			return nil, fmt.Errorf("parsing scan data: %w (line-by-line also failed: %v)", err, lineErr)
		}
		return candidates, nil
	}

	return recordsToCandidates(records), nil
}

// ParseNDJSON parses newline-delimited JSON (one masscan record per line).
func ParseNDJSON(r io.Reader) ([]proxy.Candidate, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading scan data: %w", err)
	}
	return parseLineByLine(data)
}

// cleanMasscanJSON fixes common masscan JSON issues.
func cleanMasscanJSON(data []byte) []byte {
	n := len(data)
	if n == 0 {
		return []byte("[]")
	}

	// Trim trailing whitespace
	for n > 0 && (data[n-1] == ' ' || data[n-1] == '\n' || data[n-1] == '\r' || data[n-1] == '\t') {
		n--
	}
	data = data[:n]

	if n == 0 {
		return []byte("[]")
	}

	// If it ends with ",\n]" or ",]", remove the trailing comma
	// Work backwards: find the ] then check for comma before it
	if data[n-1] == ']' {
		// Look for trailing comma before the ]
		i := n - 2
		for i >= 0 && (data[i] == ' ' || data[i] == '\n' || data[i] == '\r' || data[i] == '\t') {
			i--
		}
		if i >= 0 && data[i] == ',' {
			// Remove the comma
			cleaned := make([]byte, 0, n)
			cleaned = append(cleaned, data[:i]...)
			cleaned = append(cleaned, data[i+1:n]...)
			return cleaned
		}
	}

	// If it doesn't end with ], it might be truncated — add ]
	if data[n-1] != ']' {
		// Check if it ends with a comma (truncated output)
		if data[n-1] == ',' {
			data = data[:n-1]
		}
		// Check if it starts with [
		if data[0] == '[' {
			data = append(data, ']')
		}
	}

	return data
}

// parseLineByLine handles masscan output that's one JSON object per line.
func parseLineByLine(data []byte) ([]proxy.Candidate, error) {
	var candidates []proxy.Candidate
	decoder := json.NewDecoder(
		io.NopCloser(
			&byteReader{data: data, pos: 0},
		),
	)

	for decoder.More() {
		var record masscanRecord
		if err := decoder.Decode(&record); err != nil {
			// Skip malformed lines
			continue
		}
		for _, port := range record.Ports {
			if port.Status == "open" && port.Proto == "tcp" {
				candidates = append(candidates, proxy.Candidate{
					IP:   record.IP,
					Port: port.Port,
				})
			}
		}
	}

	return candidates, nil
}

type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *byteReader) Close() error {
	return nil
}

// recordsToCandidates converts masscan records to proxy candidates.
func recordsToCandidates(records []masscanRecord) []proxy.Candidate {
	var candidates []proxy.Candidate
	seen := make(map[string]bool)

	for _, rec := range records {
		for _, port := range rec.Ports {
			if port.Status != "open" || port.Proto != "tcp" {
				continue
			}
			key := rec.IP + ":" + strconv.Itoa(port.Port)
			if seen[key] {
				continue
			}
			seen[key] = true
			candidates = append(candidates, proxy.Candidate{
				IP:   rec.IP,
				Port: port.Port,
			})
		}
	}

	return candidates
}

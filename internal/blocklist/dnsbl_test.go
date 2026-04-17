package blocklist

import (
	"context"
	"net"
	"sync"
	"testing"
)

type mockResolver struct {
	results map[string][]string
	err     map[string]error
	mu      sync.Mutex
}

func (m *mockResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err, ok := m.err[host]; ok {
		return nil, err
	}
	if addrs, ok := m.results[host]; ok {
		return addrs, nil
	}
	return nil, &net.DNSError{Err: "not found", Name: host}
}

func TestReverseIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.1", "1.1.168.192"},
		{"10.0.0.1", "1.0.0.10"},
		{"1.2.3.4", "4.3.2.1"},
	}
	for _, tt := range tests {
		got := reverseIP(tt.input)
		if got != tt.expected {
			t.Errorf("reverseIP(%s) = %s, want %s", tt.input, got, tt.expected)
		}
	}
}

func TestChecker_Check_NotListed(t *testing.T) {
	mock := &mockResolver{}
	c := NewChecker(
		WithLists([]string{"test.bl.example.com"}),
		WithResolver(mock),
	)

	result := c.Check(context.Background(), "192.168.1.1")
	if result.Listed {
		t.Error("expected not listed, got listed")
	}
	if len(result.Blocklists) != 0 {
		t.Errorf("expected no blocklists, got %v", result.Blocklists)
	}
}

func TestChecker_Check_Listed(t *testing.T) {
	mock := &mockResolver{
		results: map[string][]string{
			"1.1.168.192.test.bl.example.com": {"127.0.0.2"},
		},
	}
	c := NewChecker(
		WithLists([]string{"test.bl.example.com"}),
		WithResolver(mock),
	)

	result := c.Check(context.Background(), "192.168.1.1")
	if !result.Listed {
		t.Error("expected listed, got not listed")
	}
	if len(result.Blocklists) != 1 || result.Blocklists[0] != "test.bl.example.com" {
		t.Errorf("expected blocklist [test.bl.example.com], got %v", result.Blocklists)
	}
}

func TestChecker_Check_MultipleLists(t *testing.T) {
	mock := &mockResolver{
		results: map[string][]string{
			"1.0.0.10.list1.example.com": {"127.0.0.2"},
			"1.0.0.10.list2.example.com": {"127.0.0.4"},
		},
	}
	c := NewChecker(
		WithLists([]string{"list1.example.com", "list2.example.com", "list3.example.com"}),
		WithResolver(mock),
	)

	result := c.Check(context.Background(), "10.0.0.1")
	if !result.Listed {
		t.Error("expected listed")
	}
	if len(result.Blocklists) != 2 {
		t.Errorf("expected 2 blocklists, got %d", len(result.Blocklists))
	}
}

func TestResult_BlocklistsString(t *testing.T) {
	r := Result{
		Listed:     true,
		Blocklists: []string{"zen.spamhaus.org", "dnsbl.sorbs.net"},
	}
	s := r.BlocklistsString()
	if s != "zen,dnsbl" {
		t.Errorf("expected 'zen,dnsbl', got '%s'", s)
	}

	r2 := Result{Listed: false, Blocklists: nil}
	if r2.BlocklistsString() != "" {
		t.Errorf("expected empty string, got '%s'", r2.BlocklistsString())
	}
}

func TestChecker_CheckBatch(t *testing.T) {
	mock := &mockResolver{
		results: map[string][]string{
			"1.0.0.10.list.example.com": {"127.0.0.2"},
		},
	}
	c := NewChecker(
		WithLists([]string{"list.example.com"}),
		WithResolver(mock),
	)

	results := c.CheckBatch(context.Background(), []string{"10.0.0.1", "192.168.1.1"})
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if !results["10.0.0.1"].Listed {
		t.Error("expected 10.0.0.1 to be listed")
	}
	if results["192.168.1.1"].Listed {
		t.Error("expected 192.168.1.1 to not be listed")
	}
}
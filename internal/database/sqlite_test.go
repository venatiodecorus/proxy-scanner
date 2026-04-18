package database

import (
	"testing"
	"time"

	"github.com/venatiodecorus/proxy-scanner/internal/proxy"
)

func mustOpen(t *testing.T) *DB {
	t.Helper()
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("opening in-memory db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOpenAndMigrate(t *testing.T) {
	db := mustOpen(t)
	if db == nil {
		t.Fatal("expected non-nil DB")
	}
}

func TestUpsertAndGetProxy(t *testing.T) {
	db := mustOpen(t)

	p := &proxy.Proxy{
		IP:        "1.2.3.4",
		Port:      8080,
		Protocol:  proxy.ProtocolHTTP,
		Anonymity: proxy.AnonymityElite,
		Country:   "US",
		City:      "New York",
		LatencyMs: 150,
		Alive:     true,
	}

	if err := db.UpsertProxy(p); err != nil {
		t.Fatalf("upserting proxy: %v", err)
	}

	// List to find the ID
	proxies, err := db.ListProxies(proxy.ProxyFilter{AliveOnly: true})
	if err != nil {
		t.Fatalf("listing proxies: %v", err)
	}
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}

	got := proxies[0]
	if got.IP != "1.2.3.4" {
		t.Errorf("expected IP 1.2.3.4, got %s", got.IP)
	}
	if got.Port != 8080 {
		t.Errorf("expected port 8080, got %d", got.Port)
	}
	if got.Protocol != proxy.ProtocolHTTP {
		t.Errorf("expected protocol http, got %s", got.Protocol)
	}
	if got.Anonymity != proxy.AnonymityElite {
		t.Errorf("expected anonymity elite, got %s", got.Anonymity)
	}
	if got.Country != "US" {
		t.Errorf("expected country US, got %s", got.Country)
	}
	if !got.Alive {
		t.Error("expected alive=true")
	}

	// Upsert same proxy with updated fields
	p.LatencyMs = 100
	p.Country = "DE"
	if err := db.UpsertProxy(p); err != nil {
		t.Fatalf("upserting proxy (update): %v", err)
	}

	// GetProxy by ID
	updated, err := db.GetProxy(got.ID)
	if err != nil {
		t.Fatalf("getting proxy: %v", err)
	}
	if updated.LatencyMs != 100 {
		t.Errorf("expected latency 100, got %d", updated.LatencyMs)
	}
	if updated.Country != "DE" {
		t.Errorf("expected country DE, got %s", updated.Country)
	}
}

func TestListProxiesFilters(t *testing.T) {
	db := mustOpen(t)

	proxies := []*proxy.Proxy{
		{IP: "1.1.1.1", Port: 8080, Protocol: proxy.ProtocolHTTP, Anonymity: proxy.AnonymityElite, Country: "US", LatencyMs: 100, Alive: true},
		{IP: "2.2.2.2", Port: 1080, Protocol: proxy.ProtocolSOCKS5, Anonymity: proxy.AnonymityAnonymous, Country: "DE", LatencyMs: 200, Alive: true},
		{IP: "3.3.3.3", Port: 3128, Protocol: proxy.ProtocolHTTP, Anonymity: proxy.AnonymityTransparent, Country: "US", LatencyMs: 500, Alive: false},
	}
	for _, p := range proxies {
		if err := db.UpsertProxy(p); err != nil {
			t.Fatalf("upserting: %v", err)
		}
	}

	tests := []struct {
		name   string
		filter proxy.ProxyFilter
		want   int
	}{
		{"all", proxy.ProxyFilter{}, 3},
		{"alive only", proxy.ProxyFilter{AliveOnly: true}, 2},
		{"http", proxy.ProxyFilter{Protocol: proxy.ProtocolHTTP}, 2},
		{"socks5", proxy.ProxyFilter{Protocol: proxy.ProtocolSOCKS5}, 1},
		{"US", proxy.ProxyFilter{Country: "US"}, 2},
		{"elite", proxy.ProxyFilter{Anonymity: proxy.AnonymityElite}, 1},
		{"max latency 150", proxy.ProxyFilter{MaxLatency: 150}, 1},
		{"limit 1", proxy.ProxyFilter{Limit: 1}, 1},
		{"alive US http", proxy.ProxyFilter{AliveOnly: true, Protocol: proxy.ProtocolHTTP, Country: "US"}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := db.ListProxies(tt.filter)
			if err != nil {
				t.Fatalf("listing: %v", err)
			}
			if len(result) != tt.want {
				t.Errorf("expected %d proxies, got %d", tt.want, len(result))
			}
		})
	}
}

func TestRandomProxy(t *testing.T) {
	db := mustOpen(t)

	// No proxies — should return nil
	p, err := db.RandomProxy(proxy.ProxyFilter{AliveOnly: true})
	if err != nil {
		t.Fatalf("random proxy with empty db: %v", err)
	}
	if p != nil {
		t.Error("expected nil for empty db")
	}

	// Add one proxy
	if err := db.UpsertProxy(&proxy.Proxy{
		IP: "5.5.5.5", Port: 8080, Protocol: proxy.ProtocolHTTP, Alive: true,
	}); err != nil {
		t.Fatal(err)
	}

	p, err = db.RandomProxy(proxy.ProxyFilter{AliveOnly: true})
	if err != nil {
		t.Fatalf("random proxy: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil proxy")
	}
	if p.IP != "5.5.5.5" {
		t.Errorf("expected IP 5.5.5.5, got %s", p.IP)
	}
}

func TestMarkAllDead(t *testing.T) {
	db := mustOpen(t)

	for _, ip := range []string{"1.1.1.1", "2.2.2.2"} {
		db.UpsertProxy(&proxy.Proxy{IP: ip, Port: 8080, Protocol: proxy.ProtocolHTTP, Alive: true})
	}

	if err := db.MarkAllDead(); err != nil {
		t.Fatal(err)
	}

	proxies, _ := db.ListProxies(proxy.ProxyFilter{AliveOnly: true})
	if len(proxies) != 0 {
		t.Errorf("expected 0 alive proxies, got %d", len(proxies))
	}
}

func TestScanRuns(t *testing.T) {
	db := mustOpen(t)

	// No runs initially
	run, err := db.LastScanRun()
	if err != nil {
		t.Fatal(err)
	}
	if run != nil {
		t.Error("expected nil for no scan runs")
	}

	// Start a run
	id, err := db.StartScanRun()
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Error("expected non-zero run ID")
	}

	// Check it's running
	run, err = db.LastScanRun()
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "running" {
		t.Errorf("expected status running, got %s", run.Status)
	}
	if run.FinishedAt != nil {
		t.Error("expected nil finished_at for running scan")
	}

	// Finish the run
	time.Sleep(10 * time.Millisecond) // ensure time difference
	if err := db.FinishScanRun(id, 1000, 50, "completed"); err != nil {
		t.Fatal(err)
	}

	run, err = db.LastScanRun()
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "completed" {
		t.Errorf("expected status completed, got %s", run.Status)
	}
	if run.Candidates != 1000 {
		t.Errorf("expected 1000 candidates, got %d", run.Candidates)
	}
	if run.Verified != 50 {
		t.Errorf("expected 50 verified, got %d", run.Verified)
	}
	if run.FinishedAt == nil {
		t.Error("expected non-nil finished_at")
	}
}

func TestStats(t *testing.T) {
	db := mustOpen(t)

	proxies := []*proxy.Proxy{
		{IP: "1.1.1.1", Port: 8080, Protocol: proxy.ProtocolHTTP, Anonymity: proxy.AnonymityElite, Country: "US", LatencyMs: 100, Alive: true},
		{IP: "2.2.2.2", Port: 1080, Protocol: proxy.ProtocolSOCKS5, Anonymity: proxy.AnonymityAnonymous, Country: "DE", LatencyMs: 200, Alive: true},
		{IP: "3.3.3.3", Port: 3128, Protocol: proxy.ProtocolHTTP, Anonymity: proxy.AnonymityTransparent, Country: "US", LatencyMs: 500, Alive: false},
	}
	for _, p := range proxies {
		db.UpsertProxy(p)
	}

	stats, err := db.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalProxies != 3 {
		t.Errorf("expected 3 total, got %d", stats.TotalProxies)
	}
	if stats.AliveProxies != 2 {
		t.Errorf("expected 2 alive, got %d", stats.AliveProxies)
	}
	if stats.ByProtocol["http"] != 1 {
		t.Errorf("expected 1 alive http, got %d", stats.ByProtocol["http"])
	}
	if stats.ByProtocol["socks5"] != 1 {
		t.Errorf("expected 1 alive socks5, got %d", stats.ByProtocol["socks5"])
	}
	if stats.ByCountry["US"] != 1 {
		t.Errorf("expected 1 alive US, got %d", stats.ByCountry["US"])
	}
	if stats.AvgLatencyMs != 150 {
		t.Errorf("expected avg latency 150, got %d", stats.AvgLatencyMs)
	}
}

func TestEnqueueCandidates(t *testing.T) {
	db := mustOpen(t)

	candidates := []proxy.Candidate{
		{IP: "1.2.3.4", Port: 8080},
		{IP: "5.6.7.8", Port: 3128},
		{IP: "9.10.11.12", Port: 1080},
	}

	enqueued, err := db.EnqueueCandidates(candidates)
	if err != nil {
		t.Fatalf("enqueueing candidates: %v", err)
	}
	if enqueued != 3 {
		t.Errorf("expected 3 enqueued, got %d", enqueued)
	}

	pending, err := db.PendingCandidateCount()
	if err != nil {
		t.Fatalf("getting pending count: %v", err)
	}
	if pending != 3 {
		t.Errorf("expected 3 pending, got %d", pending)
	}
}

func TestEnqueueCandidatesSkipsDuplicates(t *testing.T) {
	db := mustOpen(t)

	candidates := []proxy.Candidate{
		{IP: "1.2.3.4", Port: 8080},
		{IP: "5.6.7.8", Port: 3128},
	}

	enqueued, err := db.EnqueueCandidates(candidates)
	if err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	if enqueued != 2 {
		t.Errorf("expected 2 enqueued on first call, got %d", enqueued)
	}

	enqueued, err = db.EnqueueCandidates(candidates)
	if err != nil {
		t.Fatalf("second enqueue: %v", err)
	}
	if enqueued != 0 {
		t.Errorf("expected 0 enqueued on duplicate call, got %d", enqueued)
	}

	pending, err := db.PendingCandidateCount()
	if err != nil {
		t.Fatalf("getting pending count: %v", err)
	}
	if pending != 2 {
		t.Errorf("expected 2 pending, got %d", pending)
	}
}

func TestDequeueCandidates(t *testing.T) {
	db := mustOpen(t)

	candidates := []proxy.Candidate{
		{IP: "1.2.3.4", Port: 8080},
		{IP: "5.6.7.8", Port: 3128},
		{IP: "9.10.11.12", Port: 1080},
	}

	_, err := db.EnqueueCandidates(candidates)
	if err != nil {
		t.Fatalf("enqueueing: %v", err)
	}

	entries, err := db.DequeueCandidates(2)
	if err != nil {
		t.Fatalf("dequeueing: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	for i, e := range entries {
		if e.Status != proxy.CandidateStatusProcessing {
			t.Errorf("entry %d: expected status processing, got %s", i, e.Status)
		}
		if e.IP == "" || e.Port == 0 {
			t.Errorf("entry %d: got empty IP or port", i)
		}
	}

	pending, _ := db.PendingCandidateCount()
	if pending != 1 {
		t.Errorf("expected 1 remaining pending, got %d", pending)
	}

	entries2, err := db.DequeueCandidates(10)
	if err != nil {
		t.Fatalf("second dequeue: %v", err)
	}
	if len(entries2) != 1 {
		t.Errorf("expected 1 entry on second dequeue, got %d", len(entries2))
	}

	entries3, err := db.DequeueCandidates(10)
	if err != nil {
		t.Fatalf("third dequeue: %v", err)
	}
	if len(entries3) != 0 {
		t.Errorf("expected 0 entries on empty queue, got %d", len(entries3))
	}
}

func TestDeleteCandidate(t *testing.T) {
	db := mustOpen(t)

	candidates := []proxy.Candidate{
		{IP: "1.2.3.4", Port: 8080},
		{IP: "5.6.7.8", Port: 3128},
	}

	_, err := db.EnqueueCandidates(candidates)
	if err != nil {
		t.Fatalf("enqueueing: %v", err)
	}

	entries, err := db.DequeueCandidates(1)
	if err != nil {
		t.Fatalf("dequeueing: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	if err := db.DeleteCandidate(entries[0].ID); err != nil {
		t.Fatalf("deleting candidate: %v", err)
	}

	pending, _ := db.PendingCandidateCount()
	if pending != 1 {
		t.Errorf("expected 1 remaining candidate, got %d", pending)
	}
}

func TestDeleteCandidates(t *testing.T) {
	db := mustOpen(t)

	candidates := []proxy.Candidate{
		{IP: "1.2.3.4", Port: 8080},
		{IP: "5.6.7.8", Port: 3128},
		{IP: "9.10.11.12", Port: 1080},
	}

	_, err := db.EnqueueCandidates(candidates)
	if err != nil {
		t.Fatalf("enqueueing: %v", err)
	}

	entries, err := db.DequeueCandidates(2)
	if err != nil {
		t.Fatalf("dequeueing: %v", err)
	}

	var ids []int64
	for _, e := range entries {
		ids = append(ids, e.ID)
	}

	if err := db.DeleteCandidates(ids); err != nil {
		t.Fatalf("deleting candidates: %v", err)
	}

	pending, _ := db.PendingCandidateCount()
	if pending != 1 {
		t.Errorf("expected 1 remaining candidate, got %d", pending)
	}
}

func TestResetProcessingCandidates(t *testing.T) {
	db := mustOpen(t)

	candidates := []proxy.Candidate{
		{IP: "1.2.3.4", Port: 8080},
		{IP: "5.6.7.8", Port: 3128},
		{IP: "9.10.11.12", Port: 1080},
	}

	_, err := db.EnqueueCandidates(candidates)
	if err != nil {
		t.Fatalf("enqueueing: %v", err)
	}

	_, err = db.DequeueCandidates(2)
	if err != nil {
		t.Fatalf("dequeueing: %v", err)
	}

	pending, _ := db.PendingCandidateCount()
	if pending != 1 {
		t.Errorf("expected 1 pending before reset, got %d", pending)
	}

	reset, err := db.ResetProcessingCandidates()
	if err != nil {
		t.Fatalf("resetting: %v", err)
	}
	if reset != 2 {
		t.Errorf("expected 2 reset, got %d", reset)
	}

	pending, _ = db.PendingCandidateCount()
	if pending != 3 {
		t.Errorf("expected 3 pending after reset, got %d", pending)
	}
}

func TestCandidateQueueEndToEnd(t *testing.T) {
	db := mustOpen(t)

	candidates := []proxy.Candidate{
		{IP: "1.2.3.4", Port: 8080},
		{IP: "5.6.7.8", Port: 3128},
		{IP: "9.10.11.12", Port: 1080},
	}

	enqueued, err := db.EnqueueCandidates(candidates)
	if err != nil {
		t.Fatalf("enqueueing: %v", err)
	}
	if enqueued != 3 {
		t.Errorf("expected 3 enqueued, got %d", enqueued)
	}

	entries, err := db.DequeueCandidates(10)
	if err != nil {
		t.Fatalf("dequeueing: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	for _, entry := range entries {
		if err := db.DeleteCandidate(entry.ID); err != nil {
			t.Fatalf("deleting candidate %d: %v", entry.ID, err)
		}
	}

	pending, _ := db.PendingCandidateCount()
	if pending != 0 {
		t.Errorf("expected 0 pending after processing, got %d", pending)
	}

	enqueued, err = db.EnqueueCandidates(candidates)
	if err != nil {
		t.Fatalf("re-enqueueing: %v", err)
	}
	if enqueued != 3 {
		t.Errorf("expected 3 re-enqueued after deletion, got %d", enqueued)
	}
}

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

func TestUpsertProxySetsLivenessFields(t *testing.T) {
	db := mustOpen(t)

	p := &proxy.Proxy{
		IP: "1.2.3.4", Port: 8080, Protocol: proxy.ProtocolHTTP,
		LatencyMs: 100, Alive: true,
	}
	if err := db.UpsertProxy(p); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := db.ListProxies(proxy.ProxyFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(got))
	}
	row := got[0]

	if row.Status != proxy.ProxyStatusActive {
		t.Errorf("expected status active, got %q", row.Status)
	}
	if row.CheckCount != 1 {
		t.Errorf("expected check_count=1, got %d", row.CheckCount)
	}
	if row.SuccessCount != 1 {
		t.Errorf("expected success_count=1, got %d", row.SuccessCount)
	}
	if row.ConsecutiveFailures != 0 {
		t.Errorf("expected consecutive_failures=0, got %d", row.ConsecutiveFailures)
	}
	if row.LastCheckedAt == nil {
		t.Error("expected last_checked_at to be set")
	}
	if row.LastOkAt == nil {
		t.Error("expected last_ok_at to be set")
	}

	// Re-upsert: counters should increment, consecutive_failures stays 0.
	if err := db.UpsertProxy(p); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	got, _ = db.ListProxies(proxy.ProxyFilter{})
	row = got[0]
	if row.CheckCount != 2 {
		t.Errorf("expected check_count=2 after re-upsert, got %d", row.CheckCount)
	}
	if row.SuccessCount != 2 {
		t.Errorf("expected success_count=2 after re-upsert, got %d", row.SuccessCount)
	}
}

func TestRecordCheckSuccessRecoversStaleProxy(t *testing.T) {
	db := mustOpen(t)

	p := &proxy.Proxy{IP: "1.1.1.1", Port: 8080, Protocol: proxy.ProtocolHTTP, Alive: true}
	if err := db.UpsertProxy(p); err != nil {
		t.Fatal(err)
	}
	got, _ := db.ListProxies(proxy.ProxyFilter{})
	id := got[0].ID

	// Push it to stale.
	for i := 0; i < 3; i++ {
		if err := db.RecordCheckFailure(id, 3); err != nil {
			t.Fatalf("recording failure: %v", err)
		}
	}
	got, _ = db.ListProxies(proxy.ProxyFilter{})
	if got[0].Status != proxy.ProxyStatusStale {
		t.Fatalf("expected status stale after 3 failures, got %q", got[0].Status)
	}
	if got[0].Alive {
		t.Error("expected alive=false after going stale")
	}

	// Successful recheck should restore it.
	err := db.RecordCheckSuccess(id, CheckSuccessUpdate{
		LatencyMs: 200,
		Anonymity: proxy.AnonymityElite,
		ExitIP:    "9.9.9.9",
	})
	if err != nil {
		t.Fatalf("recording success: %v", err)
	}
	got, _ = db.ListProxies(proxy.ProxyFilter{})
	row := got[0]
	if row.Status != proxy.ProxyStatusActive {
		t.Errorf("expected status active after recovery, got %q", row.Status)
	}
	if !row.Alive {
		t.Error("expected alive=true after recovery")
	}
	if row.ConsecutiveFailures != 0 {
		t.Errorf("expected consecutive_failures=0 after recovery, got %d", row.ConsecutiveFailures)
	}
	if row.LatencyMs != 200 {
		t.Errorf("expected latency 200, got %d", row.LatencyMs)
	}
	if row.ExitIP != "9.9.9.9" {
		t.Errorf("expected exit_ip 9.9.9.9, got %s", row.ExitIP)
	}
	if row.SuccessCount != 2 {
		t.Errorf("expected success_count=2, got %d", row.SuccessCount)
	}
	if row.CheckCount != 5 { // 1 upsert + 3 fails + 1 success
		t.Errorf("expected check_count=5, got %d", row.CheckCount)
	}
}

func TestRecordCheckFailureBelowThreshold(t *testing.T) {
	db := mustOpen(t)

	if err := db.UpsertProxy(&proxy.Proxy{IP: "1.1.1.1", Port: 8080, Protocol: proxy.ProtocolHTTP, Alive: true}); err != nil {
		t.Fatal(err)
	}
	got, _ := db.ListProxies(proxy.ProxyFilter{})
	id := got[0].ID

	// Two failures shouldn't flip status when threshold is 3.
	for i := 0; i < 2; i++ {
		if err := db.RecordCheckFailure(id, 3); err != nil {
			t.Fatalf("recording failure: %v", err)
		}
	}
	got, _ = db.ListProxies(proxy.ProxyFilter{})
	row := got[0]
	if row.Status != proxy.ProxyStatusActive {
		t.Errorf("expected status to remain active below threshold, got %q", row.Status)
	}
	if !row.Alive {
		t.Error("expected alive=true to remain below threshold")
	}
	if row.ConsecutiveFailures != 2 {
		t.Errorf("expected consecutive_failures=2, got %d", row.ConsecutiveFailures)
	}
}

func TestRecordCheckSuccessPreservesBlocklistByDefault(t *testing.T) {
	db := mustOpen(t)

	p := &proxy.Proxy{
		IP: "1.1.1.1", Port: 8080, Protocol: proxy.ProtocolHTTP, Alive: true,
		Blocklisted: true, Blocklists: "spamhaus",
	}
	if err := db.UpsertProxy(p); err != nil {
		t.Fatal(err)
	}
	got, _ := db.ListProxies(proxy.ProxyFilter{})
	id := got[0].ID

	// Recheck without setting blocklist — existing values should remain.
	if err := db.RecordCheckSuccess(id, CheckSuccessUpdate{LatencyMs: 50}); err != nil {
		t.Fatal(err)
	}
	got, _ = db.ListProxies(proxy.ProxyFilter{})
	row := got[0]
	if !row.Blocklisted {
		t.Error("expected blocklisted to be preserved")
	}
	if row.Blocklists != "spamhaus" {
		t.Errorf("expected blocklists=spamhaus, got %q", row.Blocklists)
	}

	// Now explicitly clear it via SetBlocklist.
	if err := db.RecordCheckSuccess(id, CheckSuccessUpdate{
		LatencyMs:    50,
		SetBlocklist: true,
		Blocklisted:  false,
		Blocklists:   "",
	}); err != nil {
		t.Fatal(err)
	}
	got, _ = db.ListProxies(proxy.ProxyFilter{})
	row = got[0]
	if row.Blocklisted {
		t.Error("expected blocklisted to be cleared")
	}
	if row.Blocklists != "" {
		t.Errorf("expected empty blocklists, got %q", row.Blocklists)
	}
}

func TestListProxiesForRecheck(t *testing.T) {
	db := mustOpen(t)

	// Three proxies.
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		if err := db.UpsertProxy(&proxy.Proxy{IP: ip, Port: 8080, Protocol: proxy.ProtocolHTTP, Alive: true}); err != nil {
			t.Fatal(err)
		}
	}

	// All were just upserted, so last_checked_at is ~now. With minAge=1h
	// none should be eligible.
	due, err := db.ListProxiesForRecheck(10, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 0 {
		t.Errorf("expected 0 due, got %d", len(due))
	}

	// Backdate one row directly so we have a deterministic candidate.
	if _, err := db.db.Exec("UPDATE proxies SET last_checked_at = ? WHERE ip = '1.1.1.1'", time.Now().UTC().Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	due, err = db.ListProxiesForRecheck(10, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 {
		t.Fatalf("expected 1 due, got %d", len(due))
	}
	if due[0].IP != "1.1.1.1" {
		t.Errorf("expected 1.1.1.1, got %s", due[0].IP)
	}

	// Limit honored.
	if _, err := db.db.Exec("UPDATE proxies SET last_checked_at = ? WHERE ip IN ('2.2.2.2','3.3.3.3')", time.Now().UTC().Add(-3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	due, _ = db.ListProxiesForRecheck(2, time.Hour)
	if len(due) != 2 {
		t.Errorf("expected limit 2, got %d", len(due))
	}
	// Oldest first: 2.2.2.2/3.3.3.3 are older than 1.1.1.1.
	if due[0].LastCheckedAt == nil || due[1].LastCheckedAt == nil {
		t.Fatal("expected last_checked_at populated")
	}
	if !due[0].LastCheckedAt.Before(*due[1].LastCheckedAt) && !due[0].LastCheckedAt.Equal(*due[1].LastCheckedAt) {
		t.Error("expected oldest last_checked_at first")
	}
}

func TestListProxiesForRecheckNullCheckedFirst(t *testing.T) {
	db := mustOpen(t)

	if err := db.UpsertProxy(&proxy.Proxy{IP: "1.1.1.1", Port: 8080, Protocol: proxy.ProtocolHTTP, Alive: true}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertProxy(&proxy.Proxy{IP: "2.2.2.2", Port: 8080, Protocol: proxy.ProtocolHTTP, Alive: true}); err != nil {
		t.Fatal(err)
	}
	// Wipe last_checked_at on one row to simulate a row from before liveness tracking.
	if _, err := db.db.Exec("UPDATE proxies SET last_checked_at = NULL WHERE ip = '2.2.2.2'"); err != nil {
		t.Fatal(err)
	}

	due, err := db.ListProxiesForRecheck(10, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 2 {
		t.Fatalf("expected 2 due, got %d", len(due))
	}
	// NULL last_checked_at must come first.
	if due[0].IP != "2.2.2.2" {
		t.Errorf("expected NULL last_checked_at row first, got %s", due[0].IP)
	}
}

func TestEvictDeadProxies(t *testing.T) {
	db := mustOpen(t)

	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		if err := db.UpsertProxy(&proxy.Proxy{IP: ip, Port: 8080, Protocol: proxy.ProtocolHTTP, Alive: true}); err != nil {
			t.Fatal(err)
		}
	}

	// 1.1.1.1 fails 3 times AND its last_ok_at is well in the past -> evict.
	if _, err := db.db.Exec("UPDATE proxies SET consecutive_failures = 3, last_ok_at = ? WHERE ip = '1.1.1.1'", time.Now().UTC().Add(-200*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// 2.2.2.2 fails 3 times but recent last_ok_at -> keep.
	if _, err := db.db.Exec("UPDATE proxies SET consecutive_failures = 3, last_ok_at = ? WHERE ip = '2.2.2.2'", time.Now().UTC().Add(-1*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// 3.3.3.3: only 1 failure but old last_ok_at -> keep (under threshold).
	if _, err := db.db.Exec("UPDATE proxies SET consecutive_failures = 1, last_ok_at = ? WHERE ip = '3.3.3.3'", time.Now().UTC().Add(-200*time.Hour)); err != nil {
		t.Fatal(err)
	}

	deleted, err := db.EvictDeadProxies(3, 168*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 evicted, got %d", deleted)
	}

	got, _ := db.ListProxies(proxy.ProxyFilter{})
	if len(got) != 2 {
		t.Errorf("expected 2 remaining, got %d", len(got))
	}
	for _, p := range got {
		if p.IP == "1.1.1.1" {
			t.Error("1.1.1.1 should have been evicted")
		}
	}
}

func TestMigrateBackfillsLegacyRows(t *testing.T) {
	db := mustOpen(t)

	// Insert a row via UpsertProxy (so it's correctly populated), then wipe the
	// liveness fields to simulate a row that predates liveness tracking.
	if err := db.UpsertProxy(&proxy.Proxy{IP: "1.2.3.4", Port: 8080, Protocol: proxy.ProtocolHTTP, Alive: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`UPDATE proxies SET last_checked_at = NULL, last_ok_at = NULL, status = '', check_count = 0, success_count = 0`); err != nil {
		t.Fatal(err)
	}
	if err := db.migrate(); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}

	got, _ := db.ListProxies(proxy.ProxyFilter{})
	if len(got) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(got))
	}
	row := got[0]
	if row.LastCheckedAt == nil {
		t.Error("expected last_checked_at backfilled")
	}
	if row.LastOkAt == nil {
		t.Error("expected last_ok_at backfilled")
	}
	if row.Status != proxy.ProxyStatusActive {
		t.Errorf("expected backfilled status active for alive row, got %q", row.Status)
	}
	if row.CheckCount != 1 {
		t.Errorf("expected check_count backfilled to 1, got %d", row.CheckCount)
	}
	if row.SuccessCount != 1 {
		t.Errorf("expected success_count backfilled to 1, got %d", row.SuccessCount)
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

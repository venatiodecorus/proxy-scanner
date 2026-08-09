package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/venatiodecorus/proxy-scanner/internal/blocklist"
	"github.com/venatiodecorus/proxy-scanner/internal/database"
	"github.com/venatiodecorus/proxy-scanner/internal/proxy"
)

type testResolver struct {
	addresses     []string
	err           error
	waitForCancel bool
}

func (r testResolver) LookupHost(ctx context.Context, _ string) ([]string, error) {
	if r.waitForCancel {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return r.addresses, r.err
}

func TestCheckOneIgnoresShutdownCancellation(t *testing.T) {
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.UpsertProxy(&proxy.Proxy{
		IP:       "1.2.3.4",
		Port:     1080,
		Protocol: proxy.ProtocolSOCKS5,
		Alive:    true,
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListProxies(proxy.ProxyFilter{})
	if err != nil || len(rows) != 1 {
		t.Fatalf("loading proxy: rows=%d err=%v", len(rows), err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := &revalidator{
		db: db,
		efnetChecker: blocklist.NewChecker(
			blocklist.WithResolver(testResolver{waitForCancel: true}),
			blocklist.WithLogger(logger),
		),
		logger: logger,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r.checkOne(ctx, rows[0]) {
		t.Fatal("canceled check must not succeed")
	}

	rows, err = db.ListProxies(proxy.ProxyFilter{})
	if err != nil || len(rows) != 1 {
		t.Fatalf("reloading active proxy: rows=%d err=%v", len(rows), err)
	}
	if rows[0].Status != proxy.ProxyStatusActive || !rows[0].Alive {
		t.Fatalf("shutdown cancellation changed lifecycle: status=%q alive=%v", rows[0].Status, rows[0].Alive)
	}
	if rows[0].CheckCount != 1 || rows[0].ConsecutiveFailures != 0 {
		t.Fatalf("shutdown cancellation changed counters: check_count=%d consecutive_failures=%d", rows[0].CheckCount, rows[0].ConsecutiveFailures)
	}
}

func TestCheckOneFailsClosedOnEndpointEligibility(t *testing.T) {
	tests := []struct {
		name        string
		resolver    testResolver
		blocklisted bool
	}{
		{
			name:        "listed",
			resolver:    testResolver{addresses: []string{"127.0.0.1"}},
			blocklisted: true,
		},
		{
			name: "indeterminate",
			resolver: testResolver{err: &net.DNSError{
				Err:         "server misbehaving",
				Name:        "4.3.2.1.rbl.efnetrbl.org",
				IsTemporary: true,
			}},
			blocklisted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := database.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()

			if err := db.UpsertProxy(&proxy.Proxy{
				IP:       "1.2.3.4",
				Port:     1080,
				Protocol: proxy.ProtocolSOCKS5,
				Alive:    true,
			}); err != nil {
				t.Fatal(err)
			}
			rows, err := db.ListProxies(proxy.ProxyFilter{})
			if err != nil || len(rows) != 1 {
				t.Fatalf("loading proxy: rows=%d err=%v", len(rows), err)
			}

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			r := &revalidator{
				db: db,
				efnetChecker: blocklist.NewChecker(
					blocklist.WithResolver(tt.resolver),
					blocklist.WithLogger(logger),
				),
				logger: logger,
			}

			if r.checkOne(context.Background(), rows[0]) {
				t.Fatal("expected eligibility failure")
			}

			rows, err = db.ListProxies(proxy.ProxyFilter{Status: "all"})
			if err != nil || len(rows) != 1 {
				t.Fatalf("reloading proxy: rows=%d err=%v", len(rows), err)
			}
			if rows[0].Status != proxy.ProxyStatusStale || rows[0].Alive {
				t.Fatalf("expected stale/inactive proxy, got status=%q alive=%v", rows[0].Status, rows[0].Alive)
			}
			if rows[0].Blocklisted != tt.blocklisted {
				t.Fatalf("expected blocklisted=%v, got %v", tt.blocklisted, rows[0].Blocklisted)
			}
		})
	}
}

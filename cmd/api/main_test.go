package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/venatiodecorus/proxy-scanner/internal/database"
	"github.com/venatiodecorus/proxy-scanner/internal/proxy"
)

// newTestServer builds an apiServer backed by an in-memory database, wired
// through the same mux the real server uses so route precedence is exercised too.
func newTestServer(t *testing.T) (*apiServer, http.Handler) {
	t.Helper()
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatalf("opening in-memory db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	api := &apiServer{db: db, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/proxies", api.handleListProxies)
	mux.HandleFunc("GET /v1/proxies/random", api.handleRandomProxy)
	mux.HandleFunc("GET /v1/proxies/rotate", api.handleRotateProxy)
	mux.HandleFunc("GET /v1/proxies/{id}", api.handleGetProxy)
	return api, mux
}

func seed(t *testing.T, api *apiServer, p *proxy.Proxy) {
	t.Helper()
	if err := api.db.UpsertProxy(p); err != nil {
		t.Fatalf("seeding proxy: %v", err)
	}
}

func socks5(ip string, port int) *proxy.Proxy {
	return &proxy.Proxy{
		IP: ip, Port: port, Protocol: proxy.ProtocolSOCKS5,
		Country: "US", LatencyMs: 100, Alive: true,
	}
}

func get(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func TestRotateEndpointReturnsProxyWithURL(t *testing.T) {
	api, h := newTestServer(t)
	seed(t, api, socks5("10.0.0.1", 1080))

	rec := get(t, h, "/v1/proxies/rotate")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var got struct {
		IP       string `json:"ip"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		URL      string `json:"url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding response: %v (body %s)", err, rec.Body.String())
	}
	if got.IP != "10.0.0.1" || got.Port != 1080 {
		t.Errorf("unexpected proxy: %+v", got)
	}
	if got.URL != "socks5://10.0.0.1:1080" {
		t.Errorf("expected url socks5://10.0.0.1:1080, got %q", got.URL)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("rotating responses must not be cacheable, got Cache-Control %q", cc)
	}
}

func TestRotateEndpointCyclesProxies(t *testing.T) {
	api, h := newTestServer(t)
	const n = 4
	for i := 0; i < n; i++ {
		seed(t, api, socks5("10.0.0.1", 1080+i))
	}

	seen := map[int]bool{}
	for i := 0; i < n; i++ {
		rec := get(t, h, "/v1/proxies/rotate")
		if rec.Code != http.StatusOK {
			t.Fatalf("call %d: expected 200, got %d", i, rec.Code)
		}
		var got struct {
			Port int `json:"port"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if seen[got.Port] {
			t.Fatalf("port %d returned twice within one cycle of %d proxies", got.Port, n)
		}
		seen[got.Port] = true
	}
}

func TestRotateEndpointTextFormat(t *testing.T) {
	api, h := newTestServer(t)
	seed(t, api, socks5("10.0.0.7", 1081))

	rec := get(t, h, "/v1/proxies/rotate?format=text")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("expected text/plain, got %q", ct)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != "socks5://10.0.0.7:1081" {
		t.Errorf("expected bare proxy URL, got %q", body)
	}
}

func TestRotateEndpointFiltersByProtocol(t *testing.T) {
	api, h := newTestServer(t)
	seed(t, api, socks5("10.0.0.1", 1080))
	seed(t, api, &proxy.Proxy{
		IP: "10.0.0.2", Port: 1081, Protocol: proxy.ProtocolSOCKS4,
		Country: "DE", LatencyMs: 50, Alive: true,
	})

	for i := 0; i < 3; i++ {
		rec := get(t, h, "/v1/proxies/rotate?protocol=socks4")
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		var got struct {
			Protocol string `json:"protocol"`
			URL      string `json:"url"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Protocol != "socks4" {
			t.Fatalf("protocol filter ignored, got %q", got.Protocol)
		}
		if got.URL != "socks4://10.0.0.2:1081" {
			t.Errorf("expected socks4 url, got %q", got.URL)
		}
	}
}

func TestRotateEndpointFiltersByCountry(t *testing.T) {
	api, h := newTestServer(t)
	seed(t, api, socks5("10.0.0.1", 1080))
	seed(t, api, &proxy.Proxy{
		IP: "10.0.0.2", Port: 1081, Protocol: proxy.ProtocolSOCKS5,
		Country: "DE", LatencyMs: 50, Alive: true,
	})

	// Lowercase on purpose: parseFilter upper-cases country codes.
	rec := get(t, h, "/v1/proxies/rotate?country=de")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var got struct {
		Country string `json:"country"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Country != "DE" {
		t.Errorf("expected DE, got %q", got.Country)
	}
}

// The rotating endpoint promises a usable proxy, so blocklisted entries are
// excluded unless the caller opts in.
func TestRotateEndpointExcludesBlocklistedByDefault(t *testing.T) {
	api, h := newTestServer(t)
	p := socks5("10.0.0.9", 1080)
	p.Blocklisted = true
	seed(t, api, p)

	rec := get(t, h, "/v1/proxies/rotate")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when the only proxy is blocklisted, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = get(t, h, "/v1/proxies/rotate?blocklisted=true")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 when explicitly asking for blocklisted, got %d", rec.Code)
	}
}

func TestRotateEndpointExcludesStale(t *testing.T) {
	api, h := newTestServer(t)
	seed(t, api, socks5("10.0.0.1", 1080))
	if err := api.db.RecordEligibilityFailure(1, true, "efnet"); err != nil {
		t.Fatal(err)
	}

	rec := get(t, h, "/v1/proxies/rotate")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a stale/blocklisted pool, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRotateEndpointEmptyPool(t *testing.T) {
	_, h := newTestServer(t)

	rec := get(t, h, "/v1/proxies/rotate")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on an empty pool, got %d", rec.Code)
	}

	rec = get(t, h, "/v1/proxies/rotate?format=text")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on an empty pool in text mode, got %d", rec.Code)
	}
}

// "rotate" must be routed as a literal segment, not captured by /v1/proxies/{id}.
func TestRotateRouteTakesPrecedenceOverIDRoute(t *testing.T) {
	api, h := newTestServer(t)
	seed(t, api, socks5("10.0.0.1", 1080))

	rec := get(t, h, "/v1/proxies/rotate")
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate route was shadowed by the {id} route: got %d (%s)", rec.Code, rec.Body.String())
	}

	// And the id route still works.
	rec = get(t, h, "/v1/proxies/1")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected the id route to still resolve, got %d", rec.Code)
	}
}

func TestProxyURLDefaultsToSocks5(t *testing.T) {
	if got := proxyURL(&proxy.Proxy{IP: "1.2.3.4", Port: 1080}); got != "socks5://1.2.3.4:1080" {
		t.Errorf("expected socks5 default, got %q", got)
	}
	if got := proxyURL(&proxy.Proxy{IP: "1.2.3.4", Port: 3128, Protocol: proxy.ProtocolHTTP}); got != "http://1.2.3.4:3128" {
		t.Errorf("expected http scheme, got %q", got)
	}
}

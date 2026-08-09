package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/venatiodecorus/proxy-scanner/internal/database"
	"github.com/venatiodecorus/proxy-scanner/internal/proxy"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("api server failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	dbPath := envOrDefault("DB_PATH", "/data/proxies.db")
	listenAddr := envOrDefault("LISTEN_ADDR", ":8080")
	apiToken := os.Getenv("API_TOKEN")

	logger.Info("starting api server",
		"db_path", dbPath,
		"listen_addr", listenAddr,
		"auth_enabled", apiToken != "",
	)

	db, err := database.Open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	api := &apiServer{db: db, logger: logger}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", api.handleHealth)
	mux.HandleFunc("GET /v1/proxies", api.handleListProxies)
	mux.HandleFunc("GET /v1/proxies/random", api.handleRandomProxy)
	mux.HandleFunc("GET /v1/proxies/rotate", api.handleRotateProxy)
	mux.HandleFunc("GET /v1/proxies/{id}", api.handleGetProxy)
	mux.HandleFunc("GET /v1/stats", api.handleStats)

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      buildHandler(logger, apiToken, mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		srv.Shutdown(shutdownCtx)
	}()

	logger.Info("listening", "addr", listenAddr)
	err = srv.ListenAndServe()
	if err == http.ErrServerClosed {
		logger.Info("server shut down gracefully")
		return nil
	}

	_ = ctx // keep ctx in scope for future use
	return err
}

type apiServer struct {
	db     *database.DB
	logger *slog.Logger
}

// handleHealth returns a simple health check response.
func (a *apiServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

// handleListProxies returns a filtered list of proxies.
func (a *apiServer) handleListProxies(w http.ResponseWriter, r *http.Request) {
	filter := parseFilter(r)
	proxies, err := a.db.ListProxies(filter)
	if err != nil {
		a.logger.Error("listing proxies", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	if proxies == nil {
		proxies = []proxy.Proxy{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"proxies": proxies,
		"count":   len(proxies),
	})
}

// handleRandomProxy returns a single random proxy matching the filter.
func (a *apiServer) handleRandomProxy(w http.ResponseWriter, r *http.Request) {
	filter := parseFilter(r)
	filter.Status = proxy.ProxyStatusActive // random must always return active proxies
	p, err := a.db.RandomProxy(filter)
	if err != nil {
		a.logger.Error("getting random proxy", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	if p == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no proxies match the given filters"})
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// handleRotateProxy is the rotating endpoint: every call returns a different
// proxy, cycling through the whole matching pool before repeating. This is the
// endpoint to hit in a loop when you want a fresh proxy per request; use
// /v1/proxies for a list and /v1/proxies/random for an unweighted sample.
//
// The response is the same proxy object the other routes return, plus a `url`
// field ready to hand to a client. Add ?format=text to get bare
// `socks5://ip:port` as text/plain instead, which is convenient in shell
// pipelines:
//
//	curl -sx "$(curl -s $API/v1/proxies/rotate?format=text)" https://example.com
//
// Filters are the same optional query parameters the list route accepts —
// protocol, country, anonymity, max_latency. Two defaults differ from the other
// routes, because this endpoint's contract is "a proxy you can use right now":
// only active proxies are considered, and blocklisted ones are excluded unless
// you explicitly ask for them with ?blocklisted=true.
func (a *apiServer) handleRotateProxy(w http.ResponseWriter, r *http.Request) {
	filter := parseFilter(r)
	filter.Status = proxy.ProxyStatusActive
	if filter.Blocklisted == nil {
		notBlocklisted := false
		filter.Blocklisted = &notBlocklisted
	}
	// Rotation returns exactly one proxy; the list route's limit/offset are
	// meaningless here and would only confuse the query.
	filter.Limit = 0
	filter.Offset = 0

	p, err := a.db.RotateProxy(filter)
	if err != nil {
		a.logger.Error("rotating proxy", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	if p == nil {
		if r.URL.Query().Get("format") == "text" {
			http.Error(w, "no proxies match the given filters", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no proxies match the given filters"})
		return
	}

	if r.URL.Query().Get("format") == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, proxyURL(p)+"\n")
		return
	}

	// Rotating responses must never be cached, or a caching client would defeat
	// the whole point of the endpoint.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, rotateResponse{Proxy: p, URL: proxyURL(p)})
}

// rotateResponse embeds the proxy so the JSON shape stays a superset of what the
// other proxy routes return, with the ready-to-use URL added alongside.
type rotateResponse struct {
	*proxy.Proxy
	URL string `json:"url"`
}

// proxyURL renders a proxy as a connection URL, e.g. socks5://1.2.3.4:1080.
func proxyURL(p *proxy.Proxy) string {
	scheme := string(p.Protocol)
	if scheme == "" {
		scheme = string(proxy.ProtocolSOCKS5)
	}
	return fmt.Sprintf("%s://%s:%d", scheme, p.IP, p.Port)
}

// handleGetProxy returns a single proxy by ID.
func (a *apiServer) handleGetProxy(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid proxy id"})
		return
	}

	p, err := a.db.GetProxy(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// handleStats returns aggregate proxy statistics.
func (a *apiServer) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := a.db.Stats()
	if err != nil {
		a.logger.Error("getting stats", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// parseFilter extracts ProxyFilter from query parameters.
//
// Default is to return only active proxies. Override with:
//   - ?status=active  — only active (default)
//   - ?status=stale   — only stale (failing recently but kept around)
//   - ?status=all     — both
//   - ?alive=false    — legacy alias for ?status=all
func parseFilter(r *http.Request) proxy.ProxyFilter {
	q := r.URL.Query()
	f := proxy.ProxyFilter{
		Status: proxy.ProxyStatusActive, // default to active only
	}

	if v := q.Get("status"); v != "" {
		s := strings.ToLower(v)
		switch s {
		case proxy.ProxyStatusActive, proxy.ProxyStatusStale, "all":
			f.Status = s
		}
	}

	if v := q.Get("protocol"); v != "" {
		f.Protocol = proxy.Protocol(strings.ToLower(v))
	}
	if v := q.Get("anonymity"); v != "" {
		f.Anonymity = proxy.Anonymity(strings.ToLower(v))
	}
	if v := q.Get("country"); v != "" {
		f.Country = strings.ToUpper(v)
	}
	if v := q.Get("max_latency"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.MaxLatency = n
		}
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			f.Limit = n
		}
	}
	if f.Limit == 0 || f.Limit > 1000 {
		f.Limit = 100 // sane default
	}
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			f.Offset = n
		}
	}
	// Legacy: ?alive=false maps to status=all so callers that previously
	// asked for "everything including dead" still work.
	if v := q.Get("alive"); v == "false" || v == "0" {
		f.Status = "all"
	}
	if v := q.Get("blocklisted"); v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			f.Blocklisted = &b
		}
	}

	return f
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// buildHandler chains the middleware stack. Auth is only included if a token is set.
func buildHandler(logger *slog.Logger, token string, mux http.Handler) http.Handler {
	var handler http.Handler = mux
	if token != "" {
		handler = authMiddleware(token, logger, handler)
	}
	return loggingMiddleware(logger, handler)
}

// loggingMiddleware logs each request.
func loggingMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"query", r.URL.RawQuery,
			"status", wrapped.statusCode,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_addr", r.RemoteAddr,
		)
	})
}

// authMiddleware requires a valid Bearer token for all routes except /v1/health.
func authMiddleware(token string, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow health checks without auth
		if r.URL.Path == "/v1/health" {
			next.ServeHTTP(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid authorization header"})
			return
		}

		provided := auth[len(prefix):]
		if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			logger.Warn("rejected invalid api token", "remote_addr", r.RemoteAddr)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid api token"})
			return
		}

		next.ServeHTTP(w, r)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

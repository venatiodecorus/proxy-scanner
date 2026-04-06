package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
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
	filter.AliveOnly = true // random should always return alive proxies
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
func parseFilter(r *http.Request) proxy.ProxyFilter {
	q := r.URL.Query()
	f := proxy.ProxyFilter{
		AliveOnly: true, // default to alive only
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
	if v := q.Get("alive"); v == "false" || v == "0" {
		f.AliveOnly = false
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

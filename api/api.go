// Package api provides an HTTP server that exposes the proxy cache and
// embedded HTML documentation.
package api

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"proxymachine/checker"
	"proxymachine/db"
	"proxymachine/metrics"
)

//go:embed all:api_docs
var docsFS embed.FS

// Server is the HTTP API server.
type Server struct {
	manager     *checker.CheckManager
	db          *db.DB
	metrics     *metrics.Metrics
	upstreamsFn func() any // set via SetUpstreamsProvider; supplies /upstreams data
	srv         *http.Server
}

// SetUpstreamsProvider wires a provider (e.g. relay.Server.Upstreams) that supplies the
// live upstream health snapshot for GET /upstreams. Safe to leave unset (endpoint 404s).
func (s *Server) SetUpstreamsProvider(fn func() any) { s.upstreamsFn = fn }

// New creates a new Server on the given address. The *http.Server is built here (not in
// Start), so Stop always has a non-nil server even if a shutdown signal arrives during
// startup — closing the race where Stop would no-op and ListenAndServe would hang forever.
func New(addr string, manager *checker.CheckManager, database *db.DB, m *metrics.Metrics) *Server {
	if addr == "" {
		addr = ":8000"
	}
	s := &Server{manager: manager, db: database, metrics: m}
	mux := http.NewServeMux()
	mux.Handle("/docs/", http.StripPrefix("/docs/", http.FileServer(http.FS(docsFS))))
	mux.HandleFunc("/", s.handleDocs)
	mux.HandleFunc("/proxy/{type}", s.handleProxy)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ready", s.handleReady)
	mux.HandleFunc("/stats", s.handleStats)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/upstreams", s.handleUpstreams)
	s.srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
	}
	return s
}

// Start begins listening for HTTP requests. It blocks until the server stops.
func (s *Server) Start() error {
	return s.srv.ListenAndServe()
}

// Stop initiates a graceful shutdown of the server. Safe before Start and idempotent.
func (s *Server) Stop(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

func (s *Server) handleDocs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	data, err := docsFS.ReadFile("api_docs/index.html")
	if err != nil {
		http.Error(w, "documentation unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

var serveTypes = []string{"http", "https", "socks4", "socks5"}

// handleReady is a readiness probe: 200 once at least one validated upstream exists (so the
// relay/SOCKS can actually serve traffic), 503 otherwise. Distinct from /health, which is
// liveness (the process is up) and always 200. Useful as a k8s readinessProbe / LB gate.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	if s.db != nil {
		for _, t := range serveTypes {
			if n, err := s.db.CountByType(t); err == nil && n > 0 {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ready"))
				return
			}
		}
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte("no validated upstreams yet"))
}

// proxyCounts returns the number of validated proxies per type (missing/erroring types
// report 0).
func (s *Server) proxyCounts() map[string]int {
	counts := make(map[string]int, len(serveTypes))
	for _, t := range serveTypes {
		if s.db != nil {
			if n, err := s.db.CountByType(t); err == nil {
				counts[t] = n
				continue
			}
		}
		counts[t] = 0
	}
	return counts
}

// handleUpstreams serves the relay's live upstream health snapshot as JSON (addr, type,
// ewma latency, consecutive fails, circuit state). 404 if no provider is wired.
func (s *Server) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.upstreamsFn == nil {
		http.Error(w, "upstream stats unavailable", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(s.upstreamsFn())
}

// handleStats serves a JSON snapshot of validated-proxy counts and relay counters.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	out := struct {
		Proxies map[string]int   `json:"proxies"`
		Relay   metrics.Snapshot `json:"relay"`
	}{
		Proxies: s.proxyCounts(),
		Relay:   s.metrics.Snapshot(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(out)
}

// handleMetrics serves Prometheus text-format metrics: per-type proxy gauges and relay
// counters.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snap := s.metrics.Snapshot()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	bw := bufio.NewWriter(w)
	defer bw.Flush()

	fmt.Fprintln(bw, "# HELP proxymachine_proxies Number of validated proxies stored, by type.")
	fmt.Fprintln(bw, "# TYPE proxymachine_proxies gauge")
	for _, t := range serveTypes {
		n := 0
		if s.db != nil {
			if c, err := s.db.CountByType(t); err == nil {
				n = c
			}
		}
		fmt.Fprintf(bw, "proxymachine_proxies{type=%q} %d\n", t, n)
	}

	fmt.Fprintln(bw, "# HELP proxymachine_relay_requests_total Relay requests handled, by kind.")
	fmt.Fprintln(bw, "# TYPE proxymachine_relay_requests_total counter")
	fmt.Fprintf(bw, "proxymachine_relay_requests_total{kind=%q} %d\n", "http", snap.RelayHTTP)
	fmt.Fprintf(bw, "proxymachine_relay_requests_total{kind=%q} %d\n", "connect", snap.RelayConnect)
	fmt.Fprintf(bw, "proxymachine_relay_requests_total{kind=%q} %d\n", "socks5", snap.RelaySocks)

	fmt.Fprintln(bw, "# HELP proxymachine_relay_failures_total Relay requests that failed to reach any upstream.")
	fmt.Fprintln(bw, "# TYPE proxymachine_relay_failures_total counter")
	fmt.Fprintf(bw, "proxymachine_relay_failures_total %d\n", snap.RelayFailures)

	fmt.Fprintln(bw, "# HELP proxymachine_relay_upstream_attempts_total Upstream proxy dial attempts.")
	fmt.Fprintln(bw, "# TYPE proxymachine_relay_upstream_attempts_total counter")
	fmt.Fprintf(bw, "proxymachine_relay_upstream_attempts_total %d\n", snap.UpstreamAttempts)

	fmt.Fprintln(bw, "# HELP proxymachine_relay_upstream_failures_total Upstream proxy dial failures.")
	fmt.Fprintln(bw, "# TYPE proxymachine_relay_upstream_failures_total counter")
	fmt.Fprintf(bw, "proxymachine_relay_upstream_failures_total %d\n", snap.UpstreamFailures)
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	proxyType := strings.ToLower(r.PathValue("type"))
	if proxyType == "" {
		http.Error(w, "proxy type required", http.StatusBadRequest)
		return
	}
	if !isValidProxyType(proxyType) {
		http.Error(w, fmt.Sprintf("invalid proxy type: %s", proxyType), http.StatusBadRequest)
		return
	}

	// time = MAX RESPONSE TIME in seconds (float); absent → no response-time filter.
	maxResp := -1.0
	if v := r.URL.Query().Get("time"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f < 0 {
			http.Error(w, fmt.Sprintf("invalid time (max response seconds): %q", v), http.StatusBadRequest)
			return
		}
		maxResp = f
	}
	// minutes = max age since last_checked (default 30; 0 disables the age filter).
	minutes := 30
	if v := r.URL.Query().Get("minutes"); v != "" {
		m, err := strconv.Atoi(v)
		if err != nil || m < 0 {
			http.Error(w, fmt.Sprintf("invalid minutes: %q", v), http.StatusBadRequest)
			return
		}
		minutes = m
	}
	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "text" && format != "txt" {
		http.Error(w, fmt.Sprintf("unsupported format: %s", format), http.StatusBadRequest)
		return
	}

	// An empty result is 200 with an empty body (a valid "no proxies match"), not 404.
	rows := s.collectRows(proxyType, maxResp, minutes)

	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(rows)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	for _, row := range rows {
		_, _ = w.Write([]byte(row.Proxy + "\n"))
	}
}

// proxyResponseTimeLayout is how the checker writes last_checked (UTC).
const lastCheckedLayout = "2006-01-02 15:04:05"

// collectRows returns the stored proxies of a type filtered by max response time and
// max age, newest validations first. Authoritative source is the DB (it carries the
// metadata the filters need); when the DB is unavailable it degrades to the relay's
// in-memory cache (addresses only, so the metadata filters cannot be applied).
func (s *Server) collectRows(proxyType string, maxResp float64, minutes int) []db.ProxyRow {
	if s.db != nil {
		all, err := s.db.GetProxyRows(proxyType)
		if err == nil {
			cutoff := time.Now().UTC().Add(-time.Duration(minutes) * time.Minute)
			out := make([]db.ProxyRow, 0, len(all))
			for _, row := range all {
				if maxResp >= 0 && row.ResponseTime > maxResp {
					continue
				}
				if minutes > 0 {
					if ts, perr := time.ParseInLocation(lastCheckedLayout, row.LastChecked, time.UTC); perr == nil && ts.Before(cutoff) {
						continue
					}
				}
				out = append(out, row)
			}
			return out
		}
	}
	if s.manager != nil {
		var out []db.ProxyRow
		for _, p := range s.manager.Cache()[proxyType] {
			out = append(out, db.ProxyRow{Proxy: p})
		}
		return out
	}
	return nil
}

func isValidProxyType(t string) bool {
	switch t {
	case "http", "https", "socks4", "socks5":
		return true
	}
	return false
}

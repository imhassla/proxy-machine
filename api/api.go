// Package api provides an HTTP server that exposes the proxy cache and
// embedded HTML documentation.
package api

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
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
	relayAddr   string     // advertised in /proxy.pac (set via SetRelayAddr)
	sessions    *sessionStore
	srv         *http.Server
}

// SetUpstreamsProvider wires a provider (e.g. relay.Server.Upstreams) that supplies the
// live upstream health snapshot for GET /upstreams. Safe to leave unset (endpoint 404s).
func (s *Server) SetUpstreamsProvider(fn func() any) { s.upstreamsFn = fn }

// SetRelayAddr sets the relay address advertised first in /proxy.pac (empty = omit).
func (s *Server) SetRelayAddr(addr string) { s.relayAddr = addr }

// New creates a new Server on the given address. The *http.Server is built here (not in
// Start), so Stop always has a non-nil server even if a shutdown signal arrives during
// startup — closing the race where Stop would no-op and ListenAndServe would hang forever.
func New(addr string, manager *checker.CheckManager, database *db.DB, m *metrics.Metrics) *Server {
	if addr == "" {
		addr = ":8000"
	}
	s := &Server{manager: manager, db: database, metrics: m, sessions: newSessionStore(30 * time.Minute)}
	mux := http.NewServeMux()
	mux.Handle("/docs/", http.StripPrefix("/docs/", http.FileServer(http.FS(docsFS))))
	mux.HandleFunc("/", s.handleDocs)
	mux.HandleFunc("/dashboard", s.handleDashboard)
	mux.HandleFunc("/proxy/{type}", s.handleProxy)
	mux.HandleFunc("/proxy.pac", s.handlePAC)
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

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := docsFS.ReadFile("api_docs/dashboard.html")
	if err != nil {
		http.Error(w, "dashboard unavailable", http.StatusInternalServerError)
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
	switch format {
	case "json", "text", "txt", "csv", "curl", "proxychains":
	default:
		http.Error(w, fmt.Sprintf("unsupported format: %s (json|text|csv|curl|proxychains)", format), http.StatusBadRequest)
		return
	}
	// anon = anonymity tier filter (elite | anonymous | transparent | unknown); empty = any.
	anon := strings.ToLower(r.URL.Query().Get("anon"))
	if anon != "" && anon != "elite" && anon != "anonymous" && anon != "transparent" && anon != "unknown" {
		http.Error(w, fmt.Sprintf("invalid anon: %q (elite|anonymous|transparent|unknown)", anon), http.StatusBadRequest)
		return
	}

	// An empty result is 200 with an empty body (a valid "no proxies match"), not 404.
	rows := s.collectRows(proxyType, maxResp, minutes, anon)
	// pick = return a single rotating proxy (on-demand rotation); session pins it.
	if isTruthy(r.URL.Query().Get("pick")) || r.URL.Query().Get("session") != "" {
		rows = s.pickOne(proxyType, rows, r.URL.Query().Get("session"), isTruthy(r.URL.Query().Get("rotate")))
	}
	writeProxyRows(w, proxyType, format, rows)
}

// writeProxyRows renders proxy rows in the requested format.
func writeProxyRows(w http.ResponseWriter, proxyType, format string, rows []db.ProxyRow) {
	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(rows)
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "proxy,response_time,last_checked,anon\n")
		for _, row := range rows {
			fmt.Fprintf(w, "%s,%.2f,%s,%s\n", row.Proxy, row.ResponseTime, row.LastChecked, row.Anon)
		}
	case "curl":
		// One `curl -x <scheme>://host:port` line per proxy, ready to paste.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		for _, row := range rows {
			fmt.Fprintf(w, "curl -x %s://%s\n", curlScheme(proxyType), row.Proxy)
		}
	case "proxychains":
		// proxychains.conf [ProxyList] lines: "<type> <host> <port>".
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		for _, row := range rows {
			if host, port, ok := strings.Cut(row.Proxy, ":"); ok {
				fmt.Fprintf(w, "%s %s %s\n", proxyType, host, port)
			}
		}
	default: // text / txt
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		for _, row := range rows {
			_, _ = w.Write([]byte(row.Proxy + "\n"))
		}
	}
}

// curlScheme maps a stored proxy type to the scheme curl's -x expects.
func curlScheme(proxyType string) string {
	switch proxyType {
	case "socks4":
		return "socks4a"
	case "socks5":
		return "socks5h"
	case "https":
		return "https"
	default:
		return "http"
	}
}

func isTruthy(v string) bool {
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// handlePAC serves a browser proxy auto-config (PAC) pointing at the local relay, with the
// fastest fresh http proxies as ordered fallbacks and DIRECT last.
func (s *Server) handlePAC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rows := s.collectRows("http", -1, 0, "") // no age filter — list all validated http fallbacks
	n := 10
	if len(rows) < n {
		n = len(rows)
	}
	var b strings.Builder
	b.WriteString("function FindProxyForURL(url, host) {\n  return \"")
	if s.relayAddr != "" {
		fmt.Fprintf(&b, "PROXY %s; ", s.relayAddr)
	}
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "PROXY %s; ", rows[i].Proxy)
	}
	b.WriteString("DIRECT\";\n}\n")
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, b.String())
}

// proxyResponseTimeLayout is how the checker writes last_checked (UTC).
const lastCheckedLayout = "2006-01-02 15:04:05"

// collectRows returns the stored proxies of a type filtered by max response time and
// max age, newest validations first. Authoritative source is the DB (it carries the
// metadata the filters need); when the DB is unavailable it degrades to the relay's
// in-memory cache (addresses only, so the metadata filters cannot be applied).
func (s *Server) collectRows(proxyType string, maxResp float64, minutes int, anon string) []db.ProxyRow {
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
				// anon filter: "unknown" matches an empty tier; otherwise exact tier match.
				if anon != "" {
					rowTier := row.Anon
					if rowTier == "" {
						rowTier = "unknown"
					}
					if rowTier != anon {
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

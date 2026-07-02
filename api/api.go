// Package api provides an HTTP server that exposes the proxy cache and
// embedded HTML documentation.
package api

import (
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
)

//go:embed all:api_docs
var docsFS embed.FS

// Server is the HTTP API server.
type Server struct {
	manager *checker.CheckManager
	db      *db.DB
	srv     *http.Server
}

// New creates a new Server on the given address. The *http.Server is built here (not in
// Start), so Stop always has a non-nil server even if a shutdown signal arrives during
// startup — closing the race where Stop would no-op and ListenAndServe would hang forever.
func New(addr string, manager *checker.CheckManager, database *db.DB) *Server {
	if addr == "" {
		addr = ":8000"
	}
	s := &Server{manager: manager, db: database}
	mux := http.NewServeMux()
	mux.Handle("/docs/", http.StripPrefix("/docs/", http.FileServer(http.FS(docsFS))))
	mux.HandleFunc("/", s.handleDocs)
	mux.HandleFunc("/proxy/{type}", s.handleProxy)
	mux.HandleFunc("/health", s.handleHealth)
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

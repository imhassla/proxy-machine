package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxymachine/db"
	"proxymachine/metrics"
)

func TestServer_ProxyFiltering(t *testing.T) {
	// Use an in-memory DB and populate a known proxy.
	database, err := db.OpenInMemory()
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()
	if err := database.Init(); err != nil {
		t.Fatalf("init db: %v", err)
	}

	// Served from the DB (nil checker). Seed proxies with the SAME last_checked layout
	// the checker writes; one fast + one slow to exercise the response-time filter, and
	// one stale to exercise the age (minutes) filter.
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	stale := time.Now().UTC().Add(-2 * time.Hour).Format("2006-01-02 15:04:05")
	if err := database.StoreProxy("http", "10.0.0.1:3128", 0.123, now); err != nil {
		t.Fatalf("store proxy: %v", err)
	}
	if err := database.StoreProxy("http", "10.0.0.2:3128", 2.5, now); err != nil {
		t.Fatalf("store proxy: %v", err)
	}
	if err := database.StoreProxy("http", "10.0.0.9:3128", 0.05, stale); err != nil {
		t.Fatalf("store proxy: %v", err)
	}

	server := New("127.0.0.1:18000", nil, database, nil)
	go func() { _ = server.Start() }()

	base := "http://127.0.0.1:18000"
	for i := 0; i < 50; i++ {
		resp, err := http.Get(base + "/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	getRows := func(query string) []db.ProxyRow {
		t.Helper()
		resp, err := http.Get(base + query)
		if err != nil {
			t.Fatalf("request %s failed: %v", query, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: unexpected status %d", query, resp.StatusCode)
		}
		var rows []db.ProxyRow
		if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
			t.Fatalf("%s: decode json: %v", query, err)
		}
		return rows
	}

	// Default (minutes=30): the two fresh proxies, fastest first; the stale one is filtered.
	rows := getRows("/proxy/http?format=json")
	if len(rows) != 2 || rows[0].Proxy != "10.0.0.1:3128" {
		t.Fatalf("default query: got %+v, want 2 fresh rows fastest-first", rows)
	}
	if rows[0].ResponseTime != 0.123 || rows[0].LastChecked == "" {
		t.Errorf("metadata missing/wrong: %+v", rows[0])
	}

	// Response-time filter: ?time=1.5 (the docs example that used to 400) → only the fast one.
	rows = getRows("/proxy/http?time=1.5")
	if len(rows) != 1 || rows[0].Proxy != "10.0.0.1:3128" {
		t.Errorf("time=1.5 filter: got %+v, want only the <=1.5s proxy", rows)
	}

	// Age filter: a generous window surfaces the stale proxy too (3 total).
	rows = getRows("/proxy/http?minutes=10000")
	if len(rows) != 3 {
		t.Errorf("minutes=10000: got %d rows, want 3 (incl. stale)", len(rows))
	}

	// text format: newline-joined addresses.
	resp, err := http.Get(base + "/proxy/http?format=text")
	if err != nil {
		t.Fatalf("text request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "10.0.0.1:3128") {
		t.Errorf("text format missing proxy: %q", body)
	}

	// Empty result is 200 (not 404): socks4 was never populated.
	resp, err = http.Get(base + "/proxy/socks4")
	if err != nil {
		t.Fatalf("socks4 request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("empty result should be 200, got %d", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Stop(ctx); err != nil {
		t.Fatalf("stop server: %v", err)
	}
}

func TestServer_DocsRoot(t *testing.T) {
	server := New("127.0.0.1:18001", nil, nil, nil)

	go func() {
		_ = server.Start()
	}()

	base := "http://127.0.0.1:18001"
	for i := 0; i < 50; i++ {
		resp, err := http.Get(base + "/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	resp, err := http.Get(base + "/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html content type, got %q", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "Proxy-Machine API Documentation") {
		t.Errorf("documentation title not found in response body")
	}

	resp2, err := http.Get(base + "/not-found")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for non-root path, got %d", resp2.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Stop(ctx); err != nil {
		t.Fatalf("stop server: %v", err)
	}
}

func TestReadyAndStats(t *testing.T) {
	database, err := db.OpenInMemory()
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()
	if err := database.Init(); err != nil {
		t.Fatalf("init db: %v", err)
	}
	m := metrics.New()
	server := New("127.0.0.1:0", nil, database, m)

	// Empty DB → not ready (503).
	rec := httptest.NewRecorder()
	server.handleReady(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready (empty) = %d, want 503", rec.Code)
	}

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	if err := database.StoreProxy("socks4", "1.2.3.4:1080", 0.2, now); err != nil {
		t.Fatalf("store: %v", err)
	}

	// A validated upstream exists → ready (200).
	rec = httptest.NewRecorder()
	server.handleReady(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ready (with proxy) = %d, want 200", rec.Code)
	}

	// /stats reflects the proxy count and a relay counter.
	m.IncRelayConnect()
	rec = httptest.NewRecorder()
	server.handleStats(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))
	var out struct {
		Proxies map[string]int   `json:"proxies"`
		Relay   metrics.Snapshot `json:"relay"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	if out.Proxies["socks4"] != 1 {
		t.Fatalf("stats socks4 count = %d, want 1", out.Proxies["socks4"])
	}
	if out.Relay.RelayConnect != 1 {
		t.Fatalf("stats relay connect = %d, want 1", out.Relay.RelayConnect)
	}
}

func TestExportFormatsAndPAC(t *testing.T) {
	d, _ := db.OpenInMemory()
	defer d.Close()
	if err := d.Init(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	_ = d.StoreProxyTier("http", "1.1.1.1:8080", 0.1, now, "elite")
	_ = d.StoreProxyTier("http", "2.2.2.2:3128", 0.2, now, "anonymous")
	s := New("127.0.0.1:0", nil, d, nil)
	s.SetRelayAddr("127.0.0.1:3333")

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	if rec := get("/proxy/http?format=csv&minutes=0"); !strings.Contains(rec.Body.String(), "proxy,response_time,last_checked,anon") || !strings.Contains(rec.Body.String(), "1.1.1.1:8080,0.10") {
		t.Fatalf("csv format wrong:\n%s", rec.Body.String())
	}
	if rec := get("/proxy/http?format=proxychains&minutes=0"); !strings.Contains(rec.Body.String(), "http 1.1.1.1 8080") {
		t.Fatalf("proxychains format wrong:\n%s", rec.Body.String())
	}
	if rec := get("/proxy/http?format=curl&minutes=0"); !strings.Contains(rec.Body.String(), "curl -x http://1.1.1.1:8080") {
		t.Fatalf("curl format wrong:\n%s", rec.Body.String())
	}
	pac := get("/proxy.pac")
	if !strings.Contains(pac.Body.String(), "FindProxyForURL") || !strings.Contains(pac.Body.String(), "PROXY 127.0.0.1:3333") || !strings.Contains(pac.Body.String(), "DIRECT") {
		t.Fatalf("pac wrong:\n%s", pac.Body.String())
	}
}

func TestSessionRotation(t *testing.T) {
	d, _ := db.OpenInMemory()
	defer d.Close()
	if err := d.Init(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	for _, p := range []string{"1.1.1.1:80", "2.2.2.2:80", "3.3.3.3:80"} {
		_ = d.StoreProxy("http", p, 0.1, now)
	}
	s := New("127.0.0.1:0", nil, d, nil)
	pick := func(q string) string {
		rec := httptest.NewRecorder()
		s.srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/proxy/http?minutes=0&format=text&"+q, nil))
		return strings.TrimSpace(rec.Body.String())
	}
	// pick=1 returns exactly one proxy.
	one := pick("pick=1")
	if one == "" || strings.Contains(one, "\n") {
		t.Fatalf("pick=1 should return exactly one proxy, got %q", one)
	}
	// Same session returns the SAME proxy across calls.
	a := pick("session=abc")
	b := pick("session=abc")
	if a != b || a == "" {
		t.Fatalf("session pin not stable: %q vs %q", a, b)
	}
	// rotate=1 forces a fresh pick (different, given 3 proxies).
	c := pick("session=abc&rotate=1")
	if c == "" {
		t.Fatal("rotate returned empty")
	}
}

func TestServer_Dashboard(t *testing.T) {
	s := New("127.0.0.1:0", nil, nil, nil)
	rec := httptest.NewRecorder()
	s.srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/dashboard", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /dashboard: expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("GET /dashboard: expected text/html content-type, got %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<!-- PROXY-MACHINE DASHBOARD -->") {
		t.Error("GET /dashboard: marker comment '<!-- PROXY-MACHINE DASHBOARD -->' not found in response body")
	}
}

func TestGeoFilter(t *testing.T) {
	d, _ := db.OpenInMemory()
	defer d.Close()
	if err := d.Init(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	_ = d.StoreProxy("http", "1.1.1.1:80", 0.1, now)
	_ = d.StoreProxy("http", "2.2.2.2:80", 0.2, now)
	_ = d.StoreGeo([]db.GeoRow{
		{IP: "1.1.1.1", Country: "United States", CountryCode: "US", ASN: "AS13335 Cloudflare"},
		{IP: "2.2.2.2", Country: "Germany", CountryCode: "DE", ASN: "AS3320 DTAG"},
	}, now)
	s := New("127.0.0.1:0", nil, d, nil)

	get := func(q string) string {
		rec := httptest.NewRecorder()
		s.srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/proxy/http?minutes=0&format=text&"+q, nil))
		return strings.TrimSpace(rec.Body.String())
	}
	if got := get("country=US"); got != "1.1.1.1:80" {
		t.Errorf("country=US = %q, want 1.1.1.1:80", got)
	}
	if got := get("country=DE"); got != "2.2.2.2:80" {
		t.Errorf("country=DE = %q, want 2.2.2.2:80", got)
	}
	if got := get("asn=cloudflare"); got != "1.1.1.1:80" {
		t.Errorf("asn=cloudflare = %q, want 1.1.1.1:80", got)
	}
	if got := get("country=FR"); got != "" {
		t.Errorf("country=FR = %q, want empty", got)
	}
}

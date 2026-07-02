package relay

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"proxymachine/config"
)

// Stop must work even if it races server startup — the *http.Server is built in New,
// so a shutdown signal arriving before/just-after Start can't leave Stop a no-op and
// hang ListenAndServe forever (the pre-fix race).
func TestRelayStopRacesStartup(t *testing.T) {
	// Stop before Start: returns promptly, no panic.
	s := New(&config.Config{RelayAddr: "127.0.0.1:0"}, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		t.Fatalf("Stop before Start: %v", err)
	}

	// Stop immediately after launching Start: Start must return within the deadline.
	s2 := New(&config.Config{RelayAddr: "127.0.0.1:0"}, nil, nil)
	done := make(chan error, 1)
	go func() { done <- s2.Start() }()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	_ = s2.Stop(ctx2)
	select {
	case <-done: // ListenAndServe returned (ErrServerClosed or a bind error) — not hung
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after Stop — shutdown race regressed")
	}
}

// newTestRelay wires a Server whose selector serves the given upstream proxy
// addresses (host:port), bypassing the checker/db so the request path can be
// exercised in isolation (white-box: uses unexported fields).
func newTestRelay(t *testing.T, upstreams ...string) *Server {
	t.Helper()
	s := &Server{timeout: 5 * time.Second}
	s.selector = newSelector(&fakeManager{cache: map[string][]string{"http": upstreams}}, nil)
	s.pool = newTransportPool(s.timeout)
	if err := s.selector.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	return s
}

func hostPort(serverURL string) string { return strings.TrimPrefix(serverURL, "http://") }

// The relay must forward the request BODY to the upstream (the nil-body bug) and must
// STRIP hop-by-hop request headers (including any header named in Connection), while
// passing end-to-end headers through.
func TestRelayForwardsBodyAndStripsRequestHopByHop(t *testing.T) {
	var gotBody string
	var gotHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotHeaders = r.Header.Clone()
		w.Header().Set("X-Origin", "served") // end-to-end → must survive to the client
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	s := newTestRelay(t, hostPort(upstream.URL))

	req := httptest.NewRequest(http.MethodPost, "http://example.com/api", strings.NewReader("payload-123"))
	req.Header.Set("Connection", "X-Secret") // names X-Secret as hop-by-hop
	req.Header.Set("X-Secret", "leak")       // must be stripped (named in Connection)
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("X-Keep", "yes") // end-to-end → must reach upstream
	rec := httptest.NewRecorder()

	s.handleRequest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	if gotBody != "payload-123" {
		t.Errorf("upstream got body %q, want payload-123 (nil-body bug)", gotBody)
	}
	for _, h := range []string{"Connection", "Proxy-Connection", "X-Secret"} {
		if gotHeaders.Get(h) != "" {
			t.Errorf("hop-by-hop header %q leaked to upstream = %q", h, gotHeaders.Get(h))
		}
	}
	if gotHeaders.Get("X-Keep") != "yes" {
		t.Errorf("end-to-end request header X-Keep dropped (got %q)", gotHeaders.Get("X-Keep"))
	}
	if rec.Result().Header.Get("X-Origin") != "served" {
		t.Errorf("end-to-end response header X-Origin dropped")
	}
}

// stripHopByHop is deterministic and used in BOTH directions, so unit-test it directly
// (a response-direction integration assertion is unreliable — the client transport
// itself consumes the standard hop-by-hop response headers before the handler sees them).
func TestStripHopByHop(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "X-Custom-Hop, Keep-Alive")
	h.Set("X-Custom-Hop", "drop-me") // named in Connection
	h.Set("Proxy-Connection", "keep-alive")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Transfer-Encoding", "chunked")
	h.Set("Te", "trailers")
	h.Set("Upgrade", "h2c")
	h.Set("Proxy-Authorization", "Basic xxx")
	h.Set("Content-Type", "application/json") // end-to-end → must survive
	h.Set("X-App", "keep")                    // end-to-end → must survive

	stripHopByHop(h)

	for _, k := range []string{"Connection", "X-Custom-Hop", "Proxy-Connection", "Keep-Alive", "Transfer-Encoding", "Te", "Upgrade", "Proxy-Authorization"} {
		if h.Get(k) != "" {
			t.Errorf("hop-by-hop %q not stripped = %q", k, h.Get(k))
		}
	}
	if h.Get("Content-Type") != "application/json" || h.Get("X-App") != "keep" {
		t.Errorf("end-to-end headers dropped: Content-Type=%q X-App=%q", h.Get("Content-Type"), h.Get("X-App"))
	}
}

// countingUpstream is an httptest proxy that records how many requests it served.
func countingUpstream(t *testing.T, hits *int64) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(hits, 1)
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return hostPort(srv.URL)
}

// The relay must ROTATE across upstreams (round-robin), not pin every request to the
// first candidate — guards the regression where the failover loop ignored the pick.
func TestRelayRotatesAcrossUpstreams(t *testing.T) {
	var a, b, c int64
	s := newTestRelay(t, countingUpstream(t, &a), countingUpstream(t, &b), countingUpstream(t, &c))

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		rec := httptest.NewRecorder()
		s.handleRequest(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status %d", i, rec.Code)
		}
	}
	if atomic.LoadInt64(&a) != 1 || atomic.LoadInt64(&b) != 1 || atomic.LoadInt64(&c) != 1 {
		t.Fatalf("round-robin not honored across 3 healthy upstreams: a=%d b=%d c=%d (want 1/1/1)", a, b, c)
	}
}

// When the first candidate is dead, an IDEMPOTENT request fails over to the next.
func TestRelayFailsOverIdempotent(t *testing.T) {
	var live int64
	s := newTestRelay(t, "127.0.0.1:1", countingUpstream(t, &live)) // first dead, second live

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	s.handleRequest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("idempotent failover: status = %d, want 200", rec.Code)
	}
	if atomic.LoadInt64(&live) != 1 {
		t.Fatalf("failover did not reach the live upstream (hits=%d)", live)
	}
}

// A non-idempotent request (POST with a body) must NOT be replayed to the next upstream
// on a transport error — that would risk a duplicate side effect. It must 502 instead,
// and the second upstream must never be hit.
func TestRelayDoesNotReplayNonIdempotent(t *testing.T) {
	var live int64
	s := newTestRelay(t, "127.0.0.1:1", countingUpstream(t, &live)) // first dead, second live

	req := httptest.NewRequest(http.MethodPost, "http://example.com/mutate", strings.NewReader("do-it"))
	rec := httptest.NewRecorder()
	s.handleRequest(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("non-idempotent must NOT fail over: status = %d, want 502", rec.Code)
	}
	if atomic.LoadInt64(&live) != 0 {
		t.Fatalf("POST was replayed to a second upstream (hits=%d) — duplicate-side-effect hazard", live)
	}
}

// When credentials are configured the relay requires Basic Proxy-Authorization:
// missing/wrong → 407 (with a Proxy-Authenticate challenge); correct → forwarded.
func TestRelayRequiresAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	s := &Server{timeout: 5 * time.Second, user: "u", pass: "p"}
	s.selector = newSelector(&fakeManager{cache: map[string][]string{"http": {hostPort(upstream.URL)}}}, nil)
	s.pool = newTransportPool(s.timeout)
	if err := s.selector.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	basic := func(creds string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds)) }
	do := func(auth string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		if auth != "" {
			req.Header.Set("Proxy-Authorization", auth)
		}
		rec := httptest.NewRecorder()
		s.handleRequest(rec, req)
		return rec
	}

	if rec := do(""); rec.Code != http.StatusProxyAuthRequired || rec.Result().Header.Get("Proxy-Authenticate") == "" {
		t.Fatalf("no creds: status=%d challenge=%q, want 407 + Proxy-Authenticate", rec.Code, rec.Result().Header.Get("Proxy-Authenticate"))
	}
	if rec := do(basic("u:wrong")); rec.Code != http.StatusProxyAuthRequired {
		t.Errorf("wrong creds: status=%d, want 407", rec.Code)
	}
	if rec := do(basic("u:p")); rec.Code != http.StatusOK {
		t.Errorf("valid creds: status=%d, want 200", rec.Code)
	}
}

// proxyURL parses a selector candidate into the right scheme so the transport dials an
// https proxy over TLS and a socks5 proxy via SOCKS (not everything as plaintext http).
func TestProxyURL(t *testing.T) {
	cases := map[string]struct{ scheme, host string }{
		"http://1.2.3.4:8080":   {"http", "1.2.3.4:8080"},
		"https://1.2.3.4:8443":  {"https", "1.2.3.4:8443"},
		"socks5://1.2.3.4:1080": {"socks5", "1.2.3.4:1080"},
		"1.2.3.4:3128":          {"http", "1.2.3.4:3128"}, // bare → http (back-compat)
	}
	for target, want := range cases {
		u := proxyURL(target)
		if u.Scheme != want.scheme || u.Host != want.host {
			t.Errorf("proxyURL(%q) = %s://%s, want %s://%s", target, u.Scheme, u.Host, want.scheme, want.host)
		}
	}
}

// An "https"/"socks5"-typed upstream reaches the dialer with its scheme intact (so the
// transport dials TLS/SOCKS, not plaintext). The full TLS/SOCKS round-trip is exercised
// by net/http's stdlib transport; here we pin that the scheme survives selection.
func TestRelayCarriesUpstreamScheme(t *testing.T) {
	s := &Server{timeout: time.Second}
	s.selector = newSelector(&fakeManager{cache: map[string][]string{
		"https":  {"1.2.3.4:8443"},
		"socks5": {"1.2.3.4:1080"},
	}}, nil)
	if err := s.selector.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	_, cands, err := s.selector.next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, c := range cands {
		set[c] = true
		if u := proxyURL(c); (u.Scheme != "https" && u.Scheme != "socks5") || u.Host == "" {
			t.Errorf("candidate %q parsed to scheme %q host %q", c, u.Scheme, u.Host)
		}
	}
	if !set["https://1.2.3.4:8443"] || !set["socks5://1.2.3.4:1080"] {
		t.Fatalf("scheme not carried into candidates: %v", cands)
	}
}

// A request body over the cap is rejected with 413 (not buffered into OOM).
func TestRelayRejectsOversizeBody(t *testing.T) {
	var hit int64
	up := countingUpstream(t, &hit)
	s := newTestRelay(t, up)

	big := strings.NewReader(strings.Repeat("x", maxRequestBody+1))
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", big)
	rec := httptest.NewRecorder()
	s.handleRequest(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body: status = %d, want 413", rec.Code)
	}
	if atomic.LoadInt64(&hit) != 0 {
		t.Errorf("oversize body should be rejected before any upstream dial (hits=%d)", hit)
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:3333":   true,
		"localhost:3333":   true,
		"[::1]:3333":       true,
		"0.0.0.0:3333":     false,
		":3333":            false,
		"192.168.1.5:3333": false,
	}
	for addr, want := range cases {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

// All upstreams dead → 502 after exhausting the candidate list (idempotent method, so
// it actually tries every candidate before giving up).
func TestRelayAllUpstreamsDead(t *testing.T) {
	s := newTestRelay(t, "127.0.0.1:1", "127.0.0.1:2")
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	s.handleRequest(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("all-dead: status = %d, want 502", rec.Code)
	}
}

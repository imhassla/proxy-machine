package relay

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"proxymachine/metrics"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDestinationRefusalDoesNotDemoteProxy(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "blocked.example:8443" {
			w.WriteHeader(403)
			return
		}
		c, _, _ := w.(http.Hijacker).Hijack()
		defer c.Close()
		io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	}))
	defer proxy.Close()
	up := strings.TrimPrefix(proxy.URL, "http://")
	s := relayWithUpstreams(t, map[string][]string{"http": {up}})
	for i := 0; i < 4; i++ {
		if c, _, err := s.dialTunnel(context.Background(), "blocked.example:8443", ""); err == nil {
			c.Close()
			t.Fatal("blocked target accepted")
		}
	}
	if rank := s.selector.health.rank(proxy.URL); rank != 0 {
		t.Fatalf("destination refusal poisoned global health: %d", rank)
	}
	c, _, err := s.dialTunnel(context.Background(), "allowed.example:443", "")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	entries := s.Capabilities()
	if len(entries) != 2 {
		t.Fatalf("entries: %+v", entries)
	}
	for _, e := range entries {
		if e.Target == "blocked.example:8443" && (e.Stage != "connect_refused" || e.Status != 403 || e.Success) {
			t.Fatalf("wrong refusal: %+v", e)
		}
		if e.Target == "allowed.example:443" && (!e.Success || e.Stage != "connect") {
			t.Fatalf("wrong success: %+v", e)
		}
	}
}

func TestConnectCancellationUnblocksHandshake(t *testing.T) {
	accepted := make(chan struct{})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		close(accepted)
		io.Copy(io.Discard, c)
	}))
	defer proxy.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, e := dialUpstream(ctx, proxy.URL, "target.example:443", time.Minute)
		if c != nil {
			c.Close()
		}
		done <- e
	}()
	<-accepted
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("handshake ignored cancellation")
	}
}

func TestCapabilitiesBoundedExpiryAndIsolation(t *testing.T) {
	c := newCapabilities()
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	c.record("http://proxy:80", "Blocked.Example.:8443", "connect", "connect_refused", 403, false, time.Second)
	input := []string{"http://proxy:80", "http://other:80"}
	if got := c.order(input, "blocked.example:8443", "connect", false); got[0] != input[1] {
		t.Fatal(got)
	}
	if got := c.order(input, "blocked.example:443", "connect", false); got[0] != input[0] {
		t.Fatal("port scope leaked", got)
	}
	now = now.Add(failureTTL)
	if got := c.order(input, "blocked.example:8443", "connect", false); got[0] != input[0] {
		t.Fatal("expired refusal retained", got)
	}
	for i := 0; i < capabilityLimit+100; i++ {
		c.record("http://proxy:80", fmt.Sprintf("target%d:443", i), "connect", "connect", 0, true, 0)
	}
	if n := len(c.snapshot()); n != capabilityLimit {
		t.Fatal(n)
	}
	now = now.Add(capabilityTTL)
	if len(c.snapshot()) != 0 {
		t.Fatal("expired observations retained")
	}
}

func TestCapabilitiesConcurrentObservations(t *testing.T) {
	c := newCapabilities()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.record("http://proxy:80", "target:443", "connect", "connect", 0, true, 0)
				c.order([]string{"http://proxy:80"}, "target:443", "connect", true)
				c.snapshot()
			}
		}()
	}
	wg.Wait()
}

func TestOversizedDiagnosticKeysAreNotRetained(t *testing.T) {
	c := newCapabilities()
	c.record("http://proxy:80", strings.Repeat("x", 513), "connect", "connect", 0, true, 0)
	if len(c.snapshot()) != 0 {
		t.Fatal("unbounded target retained")
	}
	s := newStickyStore(time.Minute)
	s.set(strings.Repeat("x", 513), "http://proxy:80")
	if len(s.m) != 0 {
		t.Fatal("unbounded session retained")
	}
}

func TestCanceledAttemptsCountWithoutPoisoningHealth(t *testing.T) {
	s := relayWithUpstreams(t, map[string][]string{"http": {"127.0.0.1:8080"}})
	s.metrics = metrics.New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.reportTunnel(ctx, "http://127.0.0.1:8080", "target:443", context.Canceled, time.Second)
	if got := s.metrics.Snapshot(); got.UpstreamAttempts != 1 || got.UpstreamFailures != 1 {
		t.Fatal(got)
	}
	if s.metrics.FailureStages()["canceled"] != 1 || len(s.Capabilities()) != 0 || len(s.selector.health.entries()) != 0 {
		t.Fatal("caller cancellation changed route health")
	}
}

func TestProbeSOCKSURLAliases(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "probe-ok") }))
	defer origin.Close()
	for _, upstream := range []string{"socks4a://" + startSocks4Upstream(t), "socks5h://" + startSocks5Upstream(t)} {
		result, err := Probe(context.Background(), upstream, origin.URL, ProbeOptions{})
		if err != nil || !result.Success {
			t.Fatalf("%s: %+v %v", upstream, result, err)
		}
	}
}

func TestProbeOriginTLSAndBodyVerification(t *testing.T) {
	body := "controlled-origin"
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
	defer origin.Close()
	proxy := "http://" + startConnectProxy(t)
	result, err := Probe(context.Background(), proxy, origin.URL, ProbeOptions{})
	if err == nil || result.Stage != "target_tls" || result.Success {
		t.Fatalf("untrusted target accepted: %+v %v", result, err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	hash := sha256.Sum256([]byte(body))
	digest := hex.EncodeToString(hash[:])
	result, err = Probe(context.Background(), proxy, origin.URL, ProbeOptions{ExpectedSHA256: digest, RootCAs: roots})
	if err != nil || !result.Success || !result.BodyVerified {
		t.Fatalf("probe: %+v %v", result, err)
	}
	result, err = Probe(context.Background(), proxy, origin.URL, ProbeOptions{ExpectedSHA256: strings.Repeat("0", 64), RootCAs: roots})
	if err == nil || result.Stage != "body" || result.Success || result.BodyVerified {
		t.Fatalf("corruption accepted: %+v %v", result, err)
	}
}

func TestOrigin403IsForwardedWithoutProxyFailure(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403); io.WriteString(w, "origin policy") }))
	defer up.Close()
	s := relayWithUpstreams(t, map[string][]string{"http": {strings.TrimPrefix(up.URL, "http://")}})
	for i := 0; i < 4; i++ {
		rec := httptest.NewRecorder()
		s.handleRequest(rec, httptest.NewRequest("GET", "http://origin.example/", nil))
		if rec.Code != 403 || rec.Body.String() != "origin policy" {
			t.Fatal(rec)
		}
	}
	if s.selector.health.rank(up.URL) != 0 {
		t.Fatal("origin policy demoted proxy")
	}
	obs := s.Capabilities()
	if len(obs) != 1 || obs[0].Status != 403 || obs[0].Stage != "http_response" {
		t.Fatal(obs)
	}
}

func TestSuccessfulTunnelOutlivesEstablishmentDeadline(t *testing.T) {
	target := startEcho(t)
	proxy := "http://" + startConnectProxy(t)
	c, err := dialUpstream(context.Background(), proxy, target, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	time.Sleep(250 * time.Millisecond)
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte("ok"))
	b := make([]byte, 2)
	if _, err = io.ReadFull(c, b); err != nil || string(b) != "ok" {
		t.Fatalf("deadline leaked: %q %v", b, err)
	}
}

func TestStalledConnectBodyDoesNotConsumeBudget(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, _ := w.(http.Hijacker).Hijack()
		defer c.Close()
		io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 100000\r\n\r\n")
		io.Copy(io.Discard, c)
	}))
	defer proxy.Close()
	start := time.Now()
	c, err := dialUpstream(context.Background(), proxy.URL, "origin:443", 3*time.Second)
	if c != nil {
		c.Close()
	}
	stage, status := failureStage(err)
	if stage != "connect_refused" || status != 403 || time.Since(start) > time.Second {
		t.Fatalf("refusal drained: %v %s %d", err, stage, status)
	}
}

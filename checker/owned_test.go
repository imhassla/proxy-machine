package checker

import (
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"proxymachine/config"
	"proxymachine/pkg/checkservice"
)

func ownedCheckerFixture(t *testing.T, hook func(http.ResponseWriter, *http.Request) bool) (string, string) {
	t.Helper()
	s, err := checkservice.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hook != nil && !hook(w, r) {
			return
		}
		r.Header.Set("X-Real-IP", "9.9.9.9")
		r.Header.Set("X-Forwarded-For", "9.9.9.9")
		s.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.TLS.Certificates[0].Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	return s.Descriptor(ts.URL), ca
}

func TestOwnedCheckerUsesOnlyOwnedEndpoints(t *testing.T) {
	descriptor, ca := ownedCheckerFixture(t, nil)
	cm := New(&config.Config{Workers: 1, Timeout: 2 * time.Second, ConnectTimeout: time.Second, HoneypotCheck: true, CheckServiceDeep: true}, nil)
	cm.IPURLs = nil
	cm.TestURLs = nil
	trapCalls := new(atomic.Int64)
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trapCalls.Add(1)
		http.Error(w, "external canary called", 500)
	}))
	defer trap.Close()
	old := honeypotCanaries
	honeypotCanaries = []canary{{trap.URL, isPlainIP}}
	defer func() { honeypotCanaries = old }()
	if err := cm.UseOwnedService(descriptor, ca); err != nil {
		t.Fatal(err)
	}
	if cm.ValidationMode() != "owned" {
		t.Fatal("owned mode not exposed")
	}
	ip, err := cm.fetchPublicIP(context.Background())
	if err != nil || ip != "9.9.9.9" {
		t.Fatalf("owned self-IP failed: %s %v", ip, err)
	}
	proxy := httptest.NewServer(http.HandlerFunc(connectHandler))
	defer proxy.Close()
	job := proxyJob{typ: "http", addr: strings.TrimPrefix(proxy.URL, "http://")}
	if _, tier, ok := cm.check(context.Background(), "1.2.3.4", job); !ok || tier != "" {
		t.Fatalf("owned deep check failed or invented anonymity tier: ok=%v tier=%q", ok, tier)
	}
	if _, _, ok := cm.check(context.Background(), "9.9.9.9", job); ok {
		t.Fatal("accepted own IP as anonymous")
	}
	if trapCalls.Load() != 0 {
		t.Fatal("owned mode called public honeypot")
	}
}

func TestOwnedEndpointOutageDoesNotPruneStoredProxy(t *testing.T) {
	count := new(atomic.Int64)
	descriptor, ca := ownedCheckerFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		// First self-IP succeeds; the tunnel then becomes unavailable before the
		// failed candidate's direct health diagnostic. Later cycles also skip.
		if count.Add(1) > 1 {
			http.Error(w, "tunnel offline", 503)
			return false
		}
		return true
	})
	d := newTestDB(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	if err = d.StoreProxy("http", addr, 0.1, time.Now().Add(-2*time.Hour).UTC().Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}
	if err = d.StoreScanResults([]string{addr}); err != nil {
		t.Fatal(err)
	}
	cm := New(&config.Config{Workers: 1, Timeout: time.Second, ConnectTimeout: 100 * time.Millisecond, MaxProxyAge: time.Hour}, d)
	cm.ListURLs = nil
	if err = cm.UseOwnedService(descriptor, ca); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < pruneThreshold+1; i++ {
		cm.RunCycle(context.Background())
	}
	exists, err := d.ProxyExists("http", addr)
	if err != nil || !exists {
		t.Fatal("endpoint outage pruned a stored proxy")
	}
	if len(cm.recheckFails) != 0 {
		t.Fatalf("endpoint outage counted as upstream failures: %v", cm.recheckFails)
	}
	scan, err := d.GetScanResults()
	if err != nil || len(scan) != 1 {
		t.Fatal("outage consumed unvalidated scanner candidates")
	}
}

func TestOwnedHealthyEndpointStillCountsUpstreamFailure(t *testing.T) {
	descriptor, ca := ownedCheckerFixture(t, nil)
	cm := New(&config.Config{Workers: 1, Timeout: time.Second, ConnectTimeout: 100 * time.Millisecond}, nil)
	if err := cm.UseOwnedService(descriptor, ca); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	for result := range cm.validateStream(context.Background(), "1.2.3.4", []proxyJob{{typ: "http", addr: addr, recheck: true}}) {
		if result.ok || result.suspended {
			t.Fatalf("dead proxy was excused despite healthy endpoint: %+v", result)
		}
	}
}

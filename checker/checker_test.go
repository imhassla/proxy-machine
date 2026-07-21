package checker

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"proxymachine/config"
	"proxymachine/db"
)

// checkerFixture spins up a fake self-IP/test endpoint and a fake forward proxy that
// rewrites the origin (so requests through it look like a working, anonymizing proxy),
// and points the checker's globals at them. Returns the live proxy's host:port.
type checkerFixture struct {
	proxyAddr string
	listURL   string
	cleanup   func()
}

func newCheckerFixture(t *testing.T) *checkerFixture {
	t.Helper()
	ipServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := "1.2.3.4" // our "self" IP
		if r.Header.Get("Via") != "" {
			origin = "5.6.7.8" // came through the proxy → different origin → counts as alive
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"origin":"%s"}`, origin)
	}))

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		targetReq.Header = r.Header.Clone()
		targetReq.Header.Add("Via", "1.1 proxy")
		resp, err := http.DefaultClient.Do(targetReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))

	proxyParsed, _ := url.Parse(proxyServer.URL)
	proxyAddr := proxyParsed.Host

	listServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, proxyAddr+"\n")
	}))

	origIP, origTest, origLists := publicIPURLs, proxyTestURLs, publicProxyURLs
	publicIPURLs = []string{ipServer.URL}
	proxyTestURLs = []string{ipServer.URL}
	publicProxyURLs = []string{listServer.URL} // typed "http" by getProxyType

	return &checkerFixture{
		proxyAddr: proxyAddr,
		listURL:   listServer.URL,
		cleanup: func() {
			publicIPURLs, proxyTestURLs, publicProxyURLs = origIP, origTest, origLists
			ipServer.Close()
			proxyServer.Close()
			listServer.Close()
		},
	}
}

func newTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.OpenInMemory()
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := d.Init(); err != nil {
		t.Fatalf("init db: %v", err)
	}
	if err := d.EnsureScanResultsTable(); err != nil {
		t.Fatalf("ensure scan table: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// A validated public-list proxy is PERSISTED to the DB and surfaced in the cache.
func TestCheckManager_ValidatesAndPersists(t *testing.T) {
	fx := newCheckerFixture(t)
	defer fx.cleanup()
	d := newTestDB(t)
	cm := New(&config.Config{Workers: 2, Timeout: 5 * time.Second}, d)

	cm.RunCycle(context.Background())

	stored, _ := d.GetProxiesByType("http")
	if !contains(stored, fx.proxyAddr) {
		t.Fatalf("validated proxy not persisted to db: %v", stored)
	}
	if rows, _ := d.GetProxyRows("http"); len(rows) == 0 || rows[0].LastChecked == "" {
		t.Errorf("stored row missing metadata: %+v", rows)
	}
	if !contains(cm.Cache()["http"], fx.proxyAddr) {
		t.Errorf("validated proxy not in cache: %v", cm.Cache()["http"])
	}
}

// The scanner's _scan_results are validated into typed tables and then CONSUMED.
func TestCheckManager_ConsumesScanResults(t *testing.T) {
	fx := newCheckerFixture(t)
	defer fx.cleanup()
	publicProxyURLs = nil // isolate: only the scan result is a candidate
	d := newTestDB(t)
	if err := d.StoreScanResults([]string{fx.proxyAddr}); err != nil {
		t.Fatal(err)
	}
	cm := New(&config.Config{Workers: 2, Timeout: 5 * time.Second}, d)

	cm.RunCycle(context.Background())

	if stored, _ := d.GetProxiesByType("http"); !contains(stored, fx.proxyAddr) {
		t.Errorf("scan result not validated into http table: %v", stored)
	}
	if left, _ := d.GetScanResults(); len(left) != 0 {
		t.Errorf("scan results not consumed: %v", left)
	}
}

// ValidateAndStoreStream validates each ip:port off the channel as every type and stores
// survivors immediately — the streaming path used by neighbor discovery (no cycle wait).
func TestCheckManager_ValidateAndStoreStream(t *testing.T) {
	fx := newCheckerFixture(t)
	defer fx.cleanup()
	d := newTestDB(t)
	cm := New(&config.Config{Workers: 4, Timeout: 5 * time.Second}, d)

	openCh := make(chan string, 4)
	openCh <- fx.proxyAddr  // a working http proxy → stored as http
	openCh <- "127.0.0.1:1" // refuses connections → validated as nothing, stored nothing
	close(openCh)

	stored, err := cm.ValidateAndStoreStream(context.Background(), openCh)
	if err != nil {
		t.Fatalf("ValidateAndStoreStream: %v", err)
	}
	if stored < 1 {
		t.Fatalf("expected >=1 stored, got %d", stored)
	}
	if got, _ := d.GetProxiesByType("http"); !contains(got, fx.proxyAddr) {
		t.Errorf("discovered proxy not stored as http: %v", got)
	}
	// The dead candidate must not have been stored under any type.
	for _, typ := range []string{"http", "socks4", "socks5"} {
		if got, _ := d.GetProxiesByType(typ); contains(got, "127.0.0.1:1") {
			t.Errorf("dead candidate wrongly stored as %s", typ)
		}
	}
}

// Discovery attribution: a NET-NEW survivor is recorded in _discovered (counted once); a
// survivor that already existed in the pool is not, and a second pass doesn't double-count.
func TestValidateAndStoreStream_Attribution(t *testing.T) {
	fx := newCheckerFixture(t)
	defer fx.cleanup()
	d := newTestDB(t)
	cm := New(&config.Config{Workers: 4, Timeout: 5 * time.Second}, d)

	run := func() {
		ch := make(chan string, 1)
		ch <- fx.proxyAddr
		close(ch)
		if _, err := cm.ValidateAndStoreStream(context.Background(), ch); err != nil {
			t.Fatal(err)
		}
	}

	run() // first time the proxy is seen → net-new → counted
	if n, _ := d.CountDiscovered(); n != 1 {
		t.Fatalf("first pass: discovered = %d, want 1 (net-new http)", n)
	}
	run() // now already stored → not net-new, must not re-count
	if n, _ := d.CountDiscovered(); n != 1 {
		t.Fatalf("second pass: discovered = %d, want still 1 (no double-count)", n)
	}
}

// A stored proxy that no longer validates is PRUNED on recheck.
func TestCheckManager_PrunesDeadStored(t *testing.T) {
	fx := newCheckerFixture(t)
	defer fx.cleanup()
	publicProxyURLs = nil // no fresh candidates; only the recheck of the dead proxy
	d := newTestDB(t)
	const dead = "127.0.0.1:1" // refuses connections → fails validation
	if err := d.StoreProxy("http", dead, 0.5, "2020-01-01 00:00:00"); err != nil {
		t.Fatal(err)
	}
	cm := New(&config.Config{Workers: 1, Timeout: 2 * time.Second}, d)

	// Pruning has a grace period (pruneThreshold consecutive failed rechecks), so run enough
	// cycles for the dead proxy to exhaust it.
	for i := 0; i < pruneThreshold; i++ {
		cm.RunCycle(context.Background())
	}

	if stored, _ := d.GetProxiesByType("http"); contains(stored, dead) {
		t.Errorf("dead proxy not pruned after %d cycles: %v", pruneThreshold, stored)
	}
}

// Start returns nil promptly when the context is cancelled (graceful loop exit).
func TestCheckManager_StartCancels(t *testing.T) {
	fx := newCheckerFixture(t)
	defer fx.cleanup()
	d := newTestDB(t)
	cm := New(&config.Config{Workers: 1, Timeout: time.Second, CheckInterval: time.Hour}, d)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- cm.Start(ctx) }()
	// Let one cycle run, then cancel; Start must return (not block on the hour interval).
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned error on cancel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after context cancel")
	}
}

func TestNormalizeProxyLine(t *testing.T) {
	cases := []struct {
		in       string
		wantAddr string
		wantOK   bool
	}{
		{"1.2.3.4:8080", "1.2.3.4:8080", true},                  // bare (TheSpeedX/jetkai/clarketm/hookzof)
		{"http://157.66.16.38:8070", "157.66.16.38:8070", true}, // scheme:// (proxifly)
		{"socks5://208.102.51.6:58208", "208.102.51.6:58208", true},
		{"1.2.3.4:80 US", "1.2.3.4:80", true},                      // trailing country column
		{"1.2.3.4:80\t1200ms", "1.2.3.4:80", true},                 // trailing latency column
		{"  1.2.3.4:3128  ", "1.2.3.4:3128", true},                 // surrounding whitespace
		{"proxy.example.com:8080", "proxy.example.com:8080", true}, // hostname:port
		{"", "", false},                 // blank
		{"# a comment", "", false},      // comment
		{"error code: 502", "", false},  // injected junk a source may emit
		{"not-a-proxy", "", false},      // no port
		{"1.2.3.4:notaport", "", false}, // non-numeric port
		{"1.2.3.4:0", "", false},        // port out of range
		{"1.2.3.4:99999", "", false},    // port out of range
	}
	for _, c := range cases {
		gotAddr, gotOK := normalizeProxyLine(c.in)
		if gotOK != c.wantOK || gotAddr != c.wantAddr {
			t.Errorf("normalizeProxyLine(%q) = (%q,%v), want (%q,%v)", c.in, gotAddr, gotOK, c.wantAddr, c.wantOK)
		}
	}
}

// getProxyType must type each configured source URL correctly (http vs socks5), since
// the checker keys validation/storage on it.
func TestGetProxyTypeOfConfiguredSources(t *testing.T) {
	wantHTTP := []string{
		"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
		"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
		"https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
		"https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
	}
	wantSOCKS5 := []string{
		"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
		"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
		"https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
		"https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
	}
	for _, u := range wantHTTP {
		if got := getProxyType(u); got != "http" {
			t.Errorf("getProxyType(%q) = %q, want http", u, got)
		}
	}
	for _, u := range wantSOCKS5 {
		if got := getProxyType(u); got != "socks5" {
			t.Errorf("getProxyType(%q) = %q, want socks5", u, got)
		}
	}
	wantSOCKS4 := []string{
		"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
		"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
		"https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt",
	}
	for _, u := range wantSOCKS4 {
		if got := getProxyType(u); got != "socks4" {
			t.Errorf("getProxyType(%q) = %q, want socks4", u, got)
		}
	}
	// https typing must key off the path, not the "https://" scheme of every source URL.
	wantHTTPS := []string{
		"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt",
	}
	for _, u := range wantHTTPS {
		if got := getProxyType(u); got != "https" {
			t.Errorf("getProxyType(%q) = %q, want https", u, got)
		}
	}
	// Every configured type must be one the checker actually validates (testableTypes),
	// so no source is fetched then discarded.
	for _, u := range publicProxyURLs {
		typ := getProxyType(u)
		found := false
		for _, tt := range testableTypes {
			if tt == typ {
				found = true
			}
		}
		if !found {
			t.Errorf("publicProxyURLs source %q types as %q, not in testableTypes", u, typ)
		}
	}
}

// A transparent proxy that leaks the client IP in a comma-joined origin
// ("<self>, <proxy>") must be REJECTED, not stored as anonymous.
func TestCheckManager_RejectsLeakyCommaOrigin(t *testing.T) {
	ipServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := "1.2.3.4" // self
		if r.Header.Get("Via") != "" {
			origin = "1.2.3.4, 5.6.7.8" // leaky chain: self IS present
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"origin":%q}`, origin)
	}))
	defer ipServer.Close()
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out, _ := http.NewRequest(r.Method, r.URL.String(), r.Body)
		out.Header = r.Header.Clone()
		out.Header.Add("Via", "1.1 proxy")
		resp, err := http.DefaultClient.Do(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	defer proxyServer.Close()
	leaky := strings.TrimPrefix(proxyServer.URL, "http://")
	listServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, leaky)
	}))
	defer listServer.Close()

	origIP, origTest, origLists := publicIPURLs, proxyTestURLs, publicProxyURLs
	publicIPURLs, proxyTestURLs, publicProxyURLs = []string{ipServer.URL}, []string{ipServer.URL}, []string{listServer.URL}
	defer func() { publicIPURLs, proxyTestURLs, publicProxyURLs = origIP, origTest, origLists }()

	d := newTestDB(t)
	cm := New(&config.Config{Workers: 1, Timeout: 5 * time.Second}, d)
	cm.RunCycle(context.Background())

	if stored, _ := d.GetProxiesByType("http"); contains(stored, leaky) {
		t.Errorf("leaky proxy (self-IP in comma origin) was stored as anonymous: %v", stored)
	}
}

// A dead proxy that is BOTH stored in the DB and present on a public list must still be
// pruned: the public-list job (recheck=false) is added first, so the recheck flag must
// be OR'd up on dedup or the prune is skipped.
func TestCheckManager_PrunesDeadStoredEvenIfReappears(t *testing.T) {
	const dead = "127.0.0.1:1" // refuses connections
	listServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, dead) // dead proxy ALSO appears on the public list
	}))
	defer listServer.Close()
	ipServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"origin":"1.2.3.4"}`)
	}))
	defer ipServer.Close()

	origIP, origTest, origLists := publicIPURLs, proxyTestURLs, publicProxyURLs
	publicIPURLs, proxyTestURLs, publicProxyURLs = []string{ipServer.URL}, []string{ipServer.URL}, []string{listServer.URL}
	defer func() { publicIPURLs, proxyTestURLs, publicProxyURLs = origIP, origTest, origLists }()

	d := newTestDB(t)
	if err := d.StoreProxy("http", dead, 0.5, "2020-01-01 00:00:00"); err != nil {
		t.Fatal(err)
	}
	cm := New(&config.Config{Workers: 1, Timeout: time.Second}, d)
	for i := 0; i < pruneThreshold; i++ {
		cm.RunCycle(context.Background())
	}

	if stored, _ := d.GetProxiesByType("http"); contains(stored, dead) {
		t.Errorf("dead proxy present on both DB and public list was not pruned: %v", stored)
	}
}

func TestClassifyAnon(t *testing.T) {
	const sip = "1.2.3.4"
	cases := []struct {
		name       string
		res        ipResult
		wantTier   string
		wantLeaked bool
	}{
		{"no headers → unknown, not leaked", ipResult{origin: "9.9.9.9"}, "", false},
		{"origin chain leaks self → transparent", ipResult{origin: "1.2.3.4, 9.9.9.9"}, "", true},
		{"headers, no proxy markers → elite", ipResult{origin: "9.9.9.9", headers: map[string]string{"Host": "x", "User-Agent": "y"}, hasHeaders: true}, "elite", false},
		{"headers with Via → anonymous", ipResult{origin: "9.9.9.9", headers: map[string]string{"Via": "1.1 proxy"}, hasHeaders: true}, "anonymous", false},
		{"header leaks self IP → transparent", ipResult{origin: "9.9.9.9", headers: map[string]string{"X-Forwarded-For": "1.2.3.4"}, hasHeaders: true}, "transparent", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tier, leaked := classifyAnon(sip, c.res)
			if tier != c.wantTier || leaked != c.wantLeaked {
				t.Fatalf("classifyAnon = (%q, %v), want (%q, %v)", tier, leaked, c.wantTier, c.wantLeaked)
			}
		})
	}
}

func TestRecheckIntervalAdaptive(t *testing.T) {
	cm := New(&config.Config{CheckInterval: time.Minute, MaxRecheckInterval: 16 * time.Minute}, nil)
	cases := map[int]time.Duration{
		0: 1 * time.Minute,  // base
		1: 2 * time.Minute,  // base*2
		3: 8 * time.Minute,  // base*2^3
		4: 16 * time.Minute, // base*2^4 = cap
		9: 16 * time.Minute, // capped
	}
	for streak, want := range cases {
		if got := cm.recheckInterval(streak); got != want {
			t.Errorf("recheckInterval(%d) = %v, want %v", streak, got, want)
		}
	}
	// 0 cap → recheck every cycle (base).
	cm0 := New(&config.Config{CheckInterval: time.Minute, MaxRecheckInterval: 0}, nil)
	if got := cm0.recheckInterval(5); got != time.Minute {
		t.Errorf("disabled adaptive: recheckInterval(5) = %v, want 1m", got)
	}
}

func TestHoneypotClean(t *testing.T) {
	cleanIP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "203.0.113.9\n") // a normal IP echo
	}))
	defer cleanIP.Close()
	inject := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<!DOCTYPE html><html>Your account has expired. Pay now.</html>") // captive portal
	}))
	defer inject.Close()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	defer down.Close()

	ctx := context.Background()
	c := &http.Client{Timeout: 3 * time.Second}
	if !honeypotClean(ctx, c, []canary{{cleanIP.URL, isPlainIP}}) {
		t.Error("clean IP echo flagged as tampered")
	}
	if honeypotClean(ctx, c, []canary{{inject.URL, isPlainIP}}) {
		t.Error("captive-portal/HTML injection NOT detected")
	}
	// A non-responsive canary is skipped; the next responsive one decides.
	if honeypotClean(ctx, c, []canary{{down.URL, isPlainIP}, {inject.URL, isPlainIP}}) {
		t.Error("failover to the injecting canary should still detect tampering")
	}
	// All canaries down → don't penalize.
	if !honeypotClean(ctx, c, []canary{{down.URL, isPlainIP}}) {
		t.Error("all-unreachable canaries must not be treated as tampering")
	}
}

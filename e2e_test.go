package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"proxymachine/api"
	"proxymachine/checker"
	"proxymachine/config"
	"proxymachine/db"
	"proxymachine/pkg/relay"
)

// stopServer gracefully shuts a server down with a bounded deadline (vet-clean cancel).
func stopServer(stop func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = stop(ctx)
}

// TestEndToEndPipeline wires the REAL components — checker → db → api → relay — with
// fakes only at the network boundary, proving the revived pipeline works together:
// a scanned ip:port is validated, persisted, served by the API, and used by the relay
// to forward a real client request to an origin.
func TestEndToEndPipeline(t *testing.T) {
	// Fake "httpbin/ip": returns our self-IP directly, but a DIFFERENT origin when the
	// request arrived through the proxy (Via header) — the checker's anonymity oracle.
	const selfIP, proxiedIP = "1.2.3.4", "5.6.7.8"
	ipbin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := selfIP
		if r.Header.Get("Via") != "" {
			origin = proxiedIP
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"origin":%q}`, origin)
	}))
	defer ipbin.Close()

	// Fake origin the relay's client ultimately wants to reach.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ORIGIN_OK")
	}))
	defer origin.Close()

	// Fake HTTP forward proxy: forwards the (absolute-URL) request, stamping Via. Used by
	// BOTH the checker (to validate it) and the relay (to serve through it).
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		out.Header = r.Header.Clone()
		out.Header.Set("Via", "1.1 test-proxy")
		resp, err := http.DefaultClient.Do(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	defer upstream.Close()
	proxyAddr := strings.TrimPrefix(upstream.URL, "http://")

	// Real DB; seed the scanner's output (as if a scan found this open ip:port).
	database, err := db.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Init(); err != nil {
		t.Fatal(err)
	}
	if err := database.EnsureScanResultsTable(); err != nil {
		t.Fatal(err)
	}
	if err := database.StoreScanResults([]string{proxyAddr}); err != nil {
		t.Fatal(err)
	}

	// Real checker, validation endpoints pointed at the fakes; run ONE cycle.
	cfg := &config.Config{Workers: 4, Timeout: 5 * time.Second}
	mgr := checker.New(cfg, database)
	mgr.IPURLs, mgr.TestURLs, mgr.ListURLs = []string{ipbin.URL}, []string{ipbin.URL}, nil
	mgr.RunCycle(context.Background())

	// Stage 1 — checker→db: the scanned proxy validated as http and persisted; the scan
	// result was consumed.
	if got, _ := database.GetProxiesByType("http"); len(got) != 1 || got[0] != proxyAddr {
		t.Fatalf("checker→db: http table = %v, want [%s]", got, proxyAddr)
	}
	if left, _ := database.GetScanResults(); len(left) != 0 {
		t.Fatalf("scan results not consumed: %v", left)
	}

	// Stage 2 — db→api: the API serves the validated proxy with metadata.
	apiSrv := api.New("127.0.0.1:18020", mgr, database, nil)
	go func() { _ = apiSrv.Start() }()
	defer stopServer(apiSrv.Stop)
	waitReady(t, "http://127.0.0.1:18020/health")

	resp, err := http.Get("http://127.0.0.1:18020/proxy/http?format=json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []db.ProxyRow
	json.NewDecoder(resp.Body).Decode(&rows)
	resp.Body.Close()
	if len(rows) != 1 || rows[0].Proxy != proxyAddr || rows[0].LastChecked == "" {
		t.Fatalf("db→api: /proxy/http = %+v, want the validated proxy with metadata", rows)
	}

	// Stage 3 — relay: a real client request through the relay is forwarded via the
	// validated upstream proxy to the origin.
	relayCfg := &config.Config{RelayAddr: "127.0.0.1:18021", Timeout: 5 * time.Second}
	relaySrv := relay.New(relayCfg, mgr, database, nil)
	go func() { _ = relaySrv.Start() }()
	defer stopServer(relaySrv.Stop)

	relayURL, _ := url.Parse("http://127.0.0.1:18021")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(relayURL)}, Timeout: 5 * time.Second}

	var body string
	var lastErr error
	for i := 0; i < 50; i++ { // relay may not be listening yet
		r, err := client.Get(origin.URL)
		if err != nil {
			lastErr = err
			time.Sleep(20 * time.Millisecond)
			continue
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		body, lastErr = string(b), nil
		break
	}
	if lastErr != nil {
		t.Fatalf("relay request failed: %v", lastErr)
	}
	if body != "ORIGIN_OK" {
		t.Fatalf("relay did not forward to origin through the validated proxy: body = %q", body)
	}
}

func waitReady(t *testing.T, healthURL string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		resp, err := http.Get(healthURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server at %s not ready", healthURL)
}

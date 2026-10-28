package relay

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"proxymachine/config"
)

// Explicit opt-in: PROXYMACHINE_SOAK=30m go test -run TestReliabilitySoak
// -count=1 -timeout=35m -v ./pkg/relay. All endpoints are local controlled fixtures.
func TestReliabilitySoak(t *testing.T) {
	raw := os.Getenv("PROXYMACHINE_SOAK")
	if raw == "" {
		t.Skip("set PROXYMACHINE_SOAK to opt into a timed controlled soak")
	}
	duration, err := time.ParseDuration(raw)
	if err != nil || duration < time.Second {
		t.Fatal("invalid soak duration")
	}
	ws := websocketOrigin(t)
	var mu sync.Mutex
	posts := map[string]int{}
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			ws.Config.Handler.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/delay" {
			time.Sleep(20 * time.Millisecond)
		}
		if r.Method == "POST" {
			mu.Lock()
			posts[r.URL.Query().Get("id")]++
			mu.Unlock()
		}
		if r.Method == "POST" {
			io.Copy(w, io.LimitReader(r.Body, 1<<20))
		} else {
			io.WriteString(w, "controlled-soak")
		}
	}))
	defer origin.Close()
	var aDown, bDown atomic.Bool
	proxy := func(down *atomic.Bool) *httptest.Server {
		p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if down.Load() {
				http.Error(w, "injected upstream outage", 503)
				return
			}
			if r.Method != "CONNECT" {
				http.Error(w, "CONNECT required", 405)
				return
			}
			up, e := net.DialTimeout("tcp", r.Host, time.Second)
			if e != nil {
				http.Error(w, "dial failed", 502)
				return
			}
			c, br, e := w.(http.Hijacker).Hijack()
			if e != nil {
				up.Close()
				return
			}
			io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
			pipeStreams(c, br, up, time.Minute)
		}))
		t.Cleanup(p.Close)
		return p
	}
	a, b := proxy(&aDown), proxy(&bDown)
	makeRelay := func(policy string) (*Server, *httptest.Server) {
		cfg := &config.Config{SelectionPolicy: policy, Timeout: 2 * time.Second, MaxFailover: 2}
		if policy == "stable" {
			cfg.StickyHeader = "X-Proxy-Session"
		}
		s := New(cfg, nil, nil, nil)
		s.selector = newSelector(&fakeManager{cache: map[string][]string{"http": {strings.TrimPrefix(a.URL, "http://"), strings.TrimPrefix(b.URL, "http://")}}}, nil)
		s.selector.refresh(context.Background())
		server := httptest.NewServer(s.srv.Handler)
		t.Cleanup(func() { s.Stop(context.Background()); server.Close() })
		return s, server
	}
	_, rotating := makeRelay("rotate")
	_, stable := makeRelay("stable")
	type route struct {
		name          string
		tr            *http.Transport
		success, fail int
		latency       time.Duration
	}
	var routes []*route
	for _, spec := range []struct{ name, proxy string }{{"direct", ""}, {"fixed", a.URL}, {"rotate", rotating.URL}, {"stable", stable.URL}} {
		tr := &http.Transport{TLSClientConfig: origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone(), DisableKeepAlives: true, ProxyConnectHeader: http.Header{"X-Proxy-Session": {"soak"}}}
		if spec.proxy != "" {
			u, _ := url.Parse(spec.proxy)
			tr.Proxy = http.ProxyURL(u)
		}
		defer tr.CloseIdleConnections()
		routes = append(routes, &route{name: spec.name, tr: tr})
	}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	goroutines := runtime.NumGoroutine()
	start := time.Now()
	iterations := 0
	outageStage := 0
	nextReport := time.Minute
	for time.Since(start) < duration {
		stage := int(time.Since(start) * 4 / duration)
		if stage > outageStage {
			outageStage = stage
			aDown.Store(stage%2 == 1)
			bDown.Store(stage%2 == 0)
		}
		for _, route := range routes {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			id := fmt.Sprintf("%s-%d", route.name, iterations)
			method, path, payload := "GET", "/echo", ""
			switch iterations % 4 {
			case 1:
				method = "POST"
				payload = strings.Repeat("x", 68796)
			case 2:
				path = "/delay"
			case 3:
				path = "/ws"
			}
			req, _ := http.NewRequestWithContext(ctx, method, origin.URL+path+"?id="+id, strings.NewReader(payload))
			if path == "/ws" {
				req.Header.Set("Upgrade", "websocket")
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Sec-WebSocket-Version", "13")
				req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			}
			at := time.Now()
			resp, e := route.tr.RoundTrip(req)
			ok := false
			if e == nil {
				if path == "/ws" && resp.StatusCode == 101 {
					rw, yes := resp.Body.(io.ReadWriteCloser)
					if yes {
						_, e = rw.Write(maskedFrame("soak-echo"))
						frame := make([]byte, 11)
						if e == nil {
							_, e = io.ReadFull(rw, frame)
						}
						ok = e == nil && string(frame[2:]) == "soak-echo"
					}
				} else {
					body, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
					expected := "controlled-soak"
					if method == "POST" {
						expected = payload
					}
					ok = e == nil && resp.StatusCode == 200 && string(body) == expected
				}
				resp.Body.Close()
			}
			cancel()
			route.latency += time.Since(at)
			if ok {
				route.success++
			} else {
				route.fail++
				if route.name != "fixed" || !aDown.Load() {
					t.Fatalf("unexpected %s failure at iteration %d: status=%v error=%v", route.name, iterations, resp, e)
				}
			}
		}
		iterations++
		if time.Since(start) >= nextReport {
			t.Logf("elapsed=%s iterations=%d outage_stage=%d goroutines=%d", time.Since(start).Round(time.Second), iterations, outageStage, runtime.NumGoroutine())
			nextReport += time.Minute
		}
		time.Sleep(200 * time.Millisecond)
	}
	mu.Lock()
	for id, n := range posts {
		if n != 1 {
			t.Errorf("duplicate POST %s: %d", id, n)
		}
	}
	mu.Unlock()
	for _, r := range routes {
		r.tr.CloseIdleConnections()
		t.Logf("route=%s success=%d failure=%d mean_operation=%s", r.name, r.success, r.fail, r.latency/time.Duration(r.success+r.fail))
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	t.Logf("heap_before=%d heap_after=%d goroutines_before=%d goroutines_after=%d", before.HeapAlloc, after.HeapAlloc, goroutines, runtime.NumGoroutine())
	if after.HeapAlloc > before.HeapAlloc+(64<<20) {
		t.Fatal("unexpected retained heap growth")
	}
	if runtime.NumGoroutine() > goroutines+20 {
		t.Fatal("unexpected goroutine growth")
	}
}

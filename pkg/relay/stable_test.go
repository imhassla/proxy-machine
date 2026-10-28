package relay

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"proxymachine/config"
)

func TestStickyPinOutsideWindowAndHeaderIsolation(t *testing.T) {
	var hits atomic.Int64
	var leaked atomic.Bool
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("X-Proxy-Session") != "" {
			leaked.Store(true)
		}
		io.WriteString(w, "origin")
	}))
	defer up.Close()
	cache := map[string][]string{"http": {}}
	for i := 0; i < 100; i++ {
		cache["http"] = append(cache["http"], fmt.Sprintf("unused%d.invalid:8080", i))
	}
	cache["http"] = append(cache["http"], strings.TrimPrefix(up.URL, "http://"))
	s := New(&config.Config{SelectionPolicy: "stable", StickyHeader: "X-Proxy-Session", Timeout: time.Second}, nil, nil, nil)
	s.selector = newSelector(&fakeManager{cache: cache}, nil)
	s.selector.refresh(context.Background())
	s.sticky.set("session:client-1", up.URL)
	// Slow but healthy is still a valid pin: stable sessions must not churn on EWMA.
	s.selector.report(up.URL, true, 5*time.Second)
	for i := 0; i < 100; i++ {
		if i%10 == 0 {
			s.selector.refresh(context.Background())
		}
		r := httptest.NewRequest("GET", "http://origin.example/", nil)
		r.Header.Set("X-Proxy-Session", "client-1")
		w := httptest.NewRecorder()
		s.handleRequest(w, r)
		if w.Code != 200 {
			t.Fatalf("request %d: %d %s", i, w.Code, w.Body.String())
		}
	}
	if hits.Load() != 100 || leaked.Load() {
		t.Fatalf("hits=%d leaked=%v", hits.Load(), leaked.Load())
	}
}

func TestStableSOCKSSelectionAndFailover(t *testing.T) {
	a, b := startConnectProxy(t), startConnectProxy(t)
	target := startEcho(t)
	s := New(&config.Config{SelectionPolicy: "stable", Timeout: time.Second}, nil, nil, nil)
	mgr := &fakeManager{cache: map[string][]string{"http": {a, b}}}
	s.selector = newSelector(mgr, nil)
	s.selector.refresh(context.Background())
	key := "socks:" + canonicalTarget(target)
	var pinned string
	for i := 0; i < 100; i++ {
		c, err := s.socksDial(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		assertEcho(t, c)
		c.Close()
		got := s.sticky.get(key)
		if pinned == "" {
			pinned = got
		}
		if got != pinned {
			t.Fatalf("pin changed %s -> %s", pinned, got)
		}
		if i%10 == 0 {
			s.selector.refresh(context.Background())
		}
	}
	other := "http://" + b
	if pinned == other {
		other = "http://" + a
	}
	// A newly observed target refusal invalidates this target's pin, not global health.
	s.capabilities.record(pinned, target, "connect", "connect_refused", 403, false, 0)
	c, err := s.socksDial(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if s.sticky.get(key) != other {
		t.Fatal("failed pin was not replaced")
	}
}

func TestStablePinIsDiscardedWhenUpstreamRemoved(t *testing.T) {
	s := New(&config.Config{SelectionPolicy: "stable"}, nil, nil, nil)
	s.selector = newSelector(&fakeManager{cache: map[string][]string{"http": {"new:80"}}}, nil)
	s.selector.refresh(context.Background())
	if got := s.prefer([]string{"http://new:80"}, "http://removed:80", "target:443", "connect"); len(got) != 1 || got[0] != "http://new:80" {
		t.Fatal(got)
	}
}

func TestStickyStoreBounded(t *testing.T) {
	s := newStickyStore(time.Minute)
	for i := 0; i < maxStickySessions+100; i++ {
		s.set(fmt.Sprint(i), "http://proxy:80")
	}
	if len(s.m) != maxStickySessions {
		t.Fatal(len(s.m))
	}
}

func BenchmarkStablePinMembership(b *testing.B) {
	for _, n := range []int{100, 10000, 100000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			cache := map[string][]string{"http": {}}
			for i := 0; i < n; i++ {
				cache["http"] = append(cache["http"], fmt.Sprintf("proxy%d:8080", i))
			}
			selector := newSelector(&fakeManager{cache: cache}, nil)
			selector.refresh(context.Background())
			s := &Server{selector: selector}
			pinned := fmt.Sprintf("http://proxy%d:8080", n-1)
			_, candidates, _ := selector.next(context.Background())
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.prefer(candidates, pinned, "target:443", "connect")
			}
		})
	}
}

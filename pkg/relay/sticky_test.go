package relay

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestStickyStoreGetSetExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	s := newStickyStore(time.Minute)
	s.now = func() time.Time { return now }

	if got := s.get("k"); got != "" {
		t.Fatalf("empty store get = %q, want empty", got)
	}
	s.set("k", "http://1.1.1.1:80")
	if got := s.get("k"); got != "http://1.1.1.1:80" {
		t.Fatalf("get = %q, want pinned addr", got)
	}

	// A hit slides the expiry: still valid just before ttl from the LAST access.
	now = now.Add(59 * time.Second)
	if got := s.get("k"); got == "" {
		t.Fatal("pin expired too early")
	}
	now = now.Add(59 * time.Second) // slid on the previous get, so still alive
	if got := s.get("k"); got == "" {
		t.Fatal("sliding TTL did not refresh on access")
	}
	// Idle past the TTL → expires.
	now = now.Add(2 * time.Minute)
	if got := s.get("k"); got != "" {
		t.Fatalf("expired pin still returned %q", got)
	}
}

func TestMoveToFront(t *testing.T) {
	in := []string{"a", "b", "c"}
	if got := moveToFront(in, "c"); got[0] != "c" || len(got) != 3 {
		t.Fatalf("moveToFront(c) = %v", got)
	}
	if got := moveToFront(in, "zzz"); got[0] != "a" {
		t.Fatalf("moveToFront(absent) changed order: %v", got)
	}
}

// With stickiness on, every request carrying the same session header egresses through the
// SAME upstream; the other upstreams stay unused.
func TestRelayStickySession(t *testing.T) {
	var a, b, c int64
	s := newTestRelay(t, countingUpstream(t, &a), countingUpstream(t, &b), countingUpstream(t, &c))
	s.stickyHeader = "X-Session"
	s.sticky = newStickyStore(time.Minute)

	for i := 0; i < 4; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.Header.Set("X-Session", "sess-1")
		rec := httptest.NewRecorder()
		s.handleRequest(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status %d", i, rec.Code)
		}
	}

	hits := []int64{atomic.LoadInt64(&a), atomic.LoadInt64(&b), atomic.LoadInt64(&c)}
	var sum, max int64
	for _, h := range hits {
		sum += h
		if h > max {
			max = h
		}
	}
	if sum != 4 || max != 4 {
		t.Fatalf("session not pinned to one upstream: hits=%v (want all 4 on one)", hits)
	}
}

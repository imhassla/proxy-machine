package relay

import (
	"sync"
	"time"
)

// stickyStore pins a client session (keyed by a configured request-header value) to the
// upstream it last succeeded through, so sites that bind a session to the egress IP keep
// seeing the same IP. Entries use a sliding TTL: each hit refreshes the expiry, so active
// sessions stay pinned and idle ones age out. now is injectable for tests.
type stickyStore struct {
	mu  sync.Mutex
	m   map[string]stickyEntry
	ttl time.Duration
	now func() time.Time
}

type stickyEntry struct {
	addr   string
	expiry time.Time
}

func newStickyStore(ttl time.Duration) *stickyStore {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &stickyStore{m: make(map[string]stickyEntry), ttl: ttl, now: time.Now}
}

// get returns the pinned upstream for key, or "" if none/expired. A live hit slides the
// expiry forward.
func (s *stickyStore) get(key string) string {
	if key == "" {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[key]
	if !ok {
		return ""
	}
	if s.now().After(e.expiry) {
		delete(s.m, key)
		return ""
	}
	e.expiry = s.now().Add(s.ttl)
	s.m[key] = e
	return e.addr
}

// set pins key to addr with a fresh TTL.
func (s *stickyStore) set(key, addr string) {
	if key == "" || addr == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = stickyEntry{addr: addr, expiry: s.now().Add(s.ttl)}
}

// reap deletes expired pins, bounding the map when sticky keys are high-cardinality
// (per-user tokens) that never recur. Called periodically from the relay refresh loop.
func (s *stickyStore) reap() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, e := range s.m {
		if now.After(e.expiry) {
			delete(s.m, k)
		}
	}
}

// moveToFront returns cands with addr promoted to the front (if present), so a pinned
// upstream is tried first while still allowing failover to the rest.
func moveToFront(cands []string, addr string) []string {
	for i, c := range cands {
		if c == addr {
			out := make([]string, 0, len(cands))
			out = append(out, addr)
			out = append(out, cands[:i]...)
			out = append(out, cands[i+1:]...)
			return out
		}
	}
	return cands
}

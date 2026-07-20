package api

import (
	"sync"
	"time"

	"proxymachine/db"
)

// sessionStore backs on-demand rotation: a per-type round-robin counter (for ?pick=1) and
// session→proxy pins with a sliding TTL (for ?session=ID), so a client can hold a stable
// egress IP and force a fresh one with ?rotate=1.
type sessionStore struct {
	mu   sync.Mutex
	rr   map[string]uint64 // proxyType → round-robin counter
	pins map[string]pinEntry
	ttl  time.Duration
	now  func() time.Time
}

type pinEntry struct {
	proxy  string
	expiry time.Time
}

func newSessionStore(ttl time.Duration) *sessionStore {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &sessionStore{rr: map[string]uint64{}, pins: map[string]pinEntry{}, ttl: ttl, now: time.Now}
}

func (s *sessionStore) nextIndex(proxyType string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.rr[proxyType]
	s.rr[proxyType] = n + 1
	return n
}

func (s *sessionStore) getPinned(session string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.pins[session]
	if !ok || s.now().After(e.expiry) {
		delete(s.pins, session)
		return ""
	}
	e.expiry = s.now().Add(s.ttl) // sliding TTL
	s.pins[session] = e
	return e.proxy
}

func (s *sessionStore) pin(session, proxy string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pins[session] = pinEntry{proxy: proxy, expiry: s.now().Add(s.ttl)}
	// Opportunistic reap so the map can't grow unbounded with one-off sessions.
	if len(s.pins) > 1 {
		now := s.now()
		for k, e := range s.pins {
			if now.After(e.expiry) {
				delete(s.pins, k)
			}
		}
	}
}

// pickOne reduces rows to a SINGLE proxy for on-demand rotation. With a session it returns
// the pinned proxy (unless rotate forces a fresh pick, or the pin fell out of the current
// set); otherwise it round-robins across the filtered set.
func (s *Server) pickOne(proxyType string, rows []db.ProxyRow, session string, rotate bool) []db.ProxyRow {
	if len(rows) == 0 {
		return rows
	}
	if session != "" {
		if !rotate {
			if pinned := s.sessions.getPinned(session); pinned != "" {
				for _, row := range rows {
					if row.Proxy == pinned {
						return []db.ProxyRow{row}
					}
				}
			}
		}
		pick := rows[int(s.sessions.nextIndex(proxyType))%len(rows)]
		s.sessions.pin(session, pick.Proxy)
		return []db.ProxyRow{pick}
	}
	return []db.ProxyRow{rows[int(s.sessions.nextIndex(proxyType))%len(rows)]}
}

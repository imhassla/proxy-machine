package relay

import (
	"context"
	"errors"
	"sync"
)

var ErrNoProxyAvailable = errors.New("no alive proxy available")

// relayProxyTypes are the upstream proxy types the relay can dial (net/http.Transport
// supports http/https/socks5 proxy URLs). Must track checker.testableTypes — these are
// exactly the types the checker validates and stores. Candidates are carried as
// "type://addr" so the transport dials each with the correct scheme (an https proxy gets
// a TLS dial, a socks5 proxy gets SOCKS) instead of mis-dialing everything as plaintext.
var relayProxyTypes = []string{"http", "https", "socks5"}

type proxySource interface {
	Cache() map[string][]string
}

type dbSource interface {
	GetProxiesByType(proxyType string) ([]string, error)
}

type selector struct {
	manager    proxySource
	db         dbSource
	mu         sync.Mutex
	candidates []string
	nextIndex  int
}

func newSelector(manager proxySource, db dbSource) *selector {
	return &selector{
		manager: manager,
		db:      db,
	}
}

func (s *selector) refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	seen := make(map[string]struct{})
	var list []string
	add := func(typ, addr string) {
		target := typ + "://" + addr
		if _, ok := seen[target]; ok {
			return
		}
		seen[target] = struct{}{}
		list = append(list, target)
	}

	// Cache (subset of the DB) first, then the DB — both keyed by type so the scheme is
	// preserved into the candidate (dedup is per type://addr, so the same host under two
	// schemes is two distinct candidates, which is correct).
	var cache map[string][]string
	if s.manager != nil {
		cache = s.manager.Cache()
	}
	for _, typ := range relayProxyTypes {
		for _, addr := range cache[typ] {
			add(typ, addr)
		}
		if s.db != nil {
			if proxies, err := s.db.GetProxiesByType(typ); err == nil {
				for _, addr := range proxies {
					add(typ, addr)
				}
			}
		}
	}

	if len(list) == 0 {
		return ErrNoProxyAvailable
	}

	s.candidates = list
	if s.nextIndex >= len(s.candidates) {
		s.nextIndex = 0
	}
	return nil
}

func (s *selector) next(ctx context.Context) (string, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.candidates) == 0 {
		return "", nil, ErrNoProxyAvailable
	}

	idx := s.nextIndex
	pick := s.candidates[idx]
	s.nextIndex = (idx + 1) % len(s.candidates)

	// Return a fresh slice rotated to START at the pick, so a caller that iterates it
	// (for failover) honors the round-robin order instead of always egressing through
	// candidates[0]. A copy keeps the caller from mutating the selector's state.
	ordered := make([]string, len(s.candidates))
	for i := range s.candidates {
		ordered[i] = s.candidates[(idx+i)%len(s.candidates)]
	}
	return pick, ordered, nil
}

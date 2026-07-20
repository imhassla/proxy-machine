package relay

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrNoProxyAvailable = errors.New("no alive proxy available")

// relayProxyTypes are the upstream proxy types the relay can dial. Must track
// checker.testableTypes — these are exactly the types the checker validates and stores.
// Candidates are carried as "type://addr" so dialUpstream dials each with the correct
// scheme (https → TLS hop, socks4/socks5 → SOCKS handshake) instead of mis-dialing
// everything as plaintext http.
var relayProxyTypes = []string{"http", "https", "socks5", "socks4"}

type proxySource interface {
	Cache() map[string][]string
}

type dbSource interface {
	GetProxiesByType(proxyType string) ([]string, error)
}

// returnWindow bounds how many candidates next() copies + health-orders per request. The
// failover loop only tries maxFailover (default 5); returning a small rotated window keeps
// per-request allocation O(1) instead of O(total-proxies) as the DB grows, while giving
// ample failover headroom. Round-robin across requests still sweeps the whole set.
const returnWindow = 64

// minOnDemandRefresh throttles the empty-cache on-demand refresh so a burst of requests
// during a cold/empty window doesn't stampede the single SQLite connection.
const minOnDemandRefresh = 2 * time.Second

type selector struct {
	manager    proxySource
	db         dbSource
	mu         sync.Mutex
	candidates []string
	nextIndex  int
	// live is the proven-live subset (rank 0: checker-validated AND not relay-demoted),
	// rebuilt each refresh. next() round-robins STRICTLY over it (via liveIndex) so
	// consecutive requests egress through DIFFERENT working proxies (real IP rotation)
	// instead of all landing on the first survivor in the window.
	live      []string
	liveIndex int
	health    *health

	rmu         sync.Mutex // guards the on-demand refresh throttle
	refreshing  bool
	lastRefresh time.Time
}

func newSelector(manager proxySource, db dbSource) *selector {
	return &selector{
		manager: manager,
		db:      db,
		health:  newHealth(),
	}
}

// report records a request outcome for an upstream so future selections prefer fast,
// reliable proxies and back off from failing ones (circuit breaker).
func (s *selector) report(addr string, ok bool, latency time.Duration) {
	s.health.report(addr, ok, latency)
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

	// Evict health entries for upstreams no longer in the candidate set, so the health map
	// can't grow unbounded as free-proxy addresses churn over days of uptime.
	s.health.retain(seen)

	if len(list) == 0 {
		s.candidates = nil
		s.live = nil
		return ErrNoProxyAvailable
	}

	s.candidates = list
	if s.nextIndex >= len(s.candidates) {
		s.nextIndex = 0
	}
	// Rebuild the proven-live rotation set. At cold start nothing is relay-demoted yet, so
	// this is the whole validated set → immediate diversity; as proxies fail at relay-time
	// they drop out on the next refresh, narrowing rotation to the working ones.
	s.live = s.health.provenLive(list)
	return nil
}

// tryRefresh is the on-demand refresh used when next() finds no candidates. It single-flights
// (only one refresh runs at a time) and rate-limits, so a thundering herd of relay requests
// in an empty-cache window doesn't serialize behind selector.mu + the single DB connection.
func (s *selector) tryRefresh(ctx context.Context) error {
	s.rmu.Lock()
	if s.refreshing || (!s.lastRefresh.IsZero() && time.Since(s.lastRefresh) < minOnDemandRefresh) {
		s.rmu.Unlock()
		return ErrNoProxyAvailable // another goroutine is refreshing, or we refreshed just now
	}
	s.refreshing = true
	s.rmu.Unlock()

	err := s.refresh(ctx)

	s.rmu.Lock()
	s.refreshing = false
	s.lastRefresh = time.Now()
	s.rmu.Unlock()
	return err
}

// targetSet returns the current candidate set (as a lookup set) for pruning caches keyed by
// the same "type://addr" strings (e.g. the transport pool).
func (s *selector) targetSet() map[string]struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := make(map[string]struct{}, len(s.candidates))
	for _, c := range s.candidates {
		set[c] = struct{}{}
	}
	return set
}

func (s *selector) next(ctx context.Context) (string, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := len(s.candidates)
	if n == 0 {
		return "", nil, ErrNoProxyAvailable
	}

	idx := s.nextIndex
	s.nextIndex = (idx + 1) % n

	// Copy a bounded rotated window (round-robin start for fairness), then health-order just
	// that window so alive/fast upstreams lead and circuit-open ones sink — O(returnWindow),
	// not O(n). This is the failover set.
	w := returnWindow
	if w > n {
		w = n
	}
	window := make([]string, w)
	for i := 0; i < w; i++ {
		window[i] = s.candidates[(idx+i)%n]
	}
	ordered := s.health.order(window)

	// IP-rotation: pick the NEXT proven-live proxy round-robin (diverse exits), then use the
	// health-ordered window as failover. Without a live set (cold start) fall back to the
	// window's head.
	if len(s.live) > 0 {
		pick := s.live[s.liveIndex%len(s.live)]
		s.liveIndex++
		out := make([]string, 0, len(ordered)+1)
		out = append(out, pick)
		for _, c := range ordered {
			if c != pick {
				out = append(out, c)
			}
		}
		return pick, out, nil
	}
	return ordered[0], ordered, nil
}

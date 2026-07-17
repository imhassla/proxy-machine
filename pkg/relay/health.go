package relay

import (
	"sync"
	"time"
)

// Health-based upstream selection + circuit breaking. Each upstream candidate
// ("type://addr") accrues an EWMA of its successful-request latency and a run of
// consecutive failures. After failThreshold consecutive failures its circuit OPENS
// for cooldown, moving it to the back of the selection order so requests stop
// hammering a dead proxy — a single later success closes it again.
const (
	failThreshold   = 3
	circuitCooldown = 30 * time.Second
	ewmaAlpha       = 0.3 // weight of the newest sample
	// slowLatency demotes a proxy that is alive but consistently slower than this below
	// fast/unknown ones. It is a COARSE class boundary, not a strict sort key: ordering
	// strictly by latency would pin all traffic to the single fastest proxy and defeat the
	// relay's IP rotation, so within a class we keep round-robin.
	slowLatency = 4.0 // seconds
)

type stat struct {
	ewma      float64   // EWMA of successful latency (seconds)
	hasData   bool      // at least one success recorded
	fails     int       // consecutive failures
	openUntil time.Time // circuit stays open until this time
}

// health tracks per-upstream reliability/latency. The zero value is not usable;
// use newHealth. now is injectable so tests don't depend on wall-clock timing.
type health struct {
	mu  sync.Mutex
	m   map[string]*stat
	now func() time.Time
}

func newHealth() *health {
	return &health{m: make(map[string]*stat), now: time.Now}
}

// report records the outcome of one attempt through addr. On success it folds the
// latency into the EWMA and closes the circuit; on failure it counts toward the
// threshold that opens the circuit.
func (h *health) report(addr string, ok bool, latency time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.m[addr]
	if s == nil {
		s = &stat{}
		h.m[addr] = s
	}
	if ok {
		lat := latency.Seconds()
		if !s.hasData {
			s.ewma = lat
			s.hasData = true
		} else {
			s.ewma = (1-ewmaAlpha)*s.ewma + ewmaAlpha*lat
		}
		s.fails = 0
		s.openUntil = time.Time{}
		return
	}
	s.fails++
	if s.fails >= failThreshold {
		s.openUntil = h.now().Add(circuitCooldown)
	}
}

// healthEntry is a point-in-time view of one upstream's health (for /upstreams).
type healthEntry struct {
	addr    string
	ewma    float64
	hasData bool
	fails   int
	open    bool
}

// load warms the health map from persisted entries (across a restart). openUntil is
// reconstructed from the fail count so a previously-tripped circuit stays demoted.
func (h *health) load(ents []healthEntry, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, e := range ents {
		st := &stat{ewma: e.ewma, hasData: e.hasData, fails: e.fails}
		if e.fails >= failThreshold {
			st.openUntil = now.Add(circuitCooldown)
		}
		h.m[e.addr] = st
	}
}

// entries returns a snapshot of every tracked upstream's health.
func (h *health) entries() []healthEntry {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	out := make([]healthEntry, 0, len(h.m))
	for addr, s := range h.m {
		out = append(out, healthEntry{addr: addr, ewma: s.ewma, hasData: s.hasData, fails: s.fails, open: s.openUntil.After(now)})
	}
	return out
}

// retain drops health entries whose addr is not in keep, so the map can't grow unbounded as
// free-proxy addresses churn. Called on each selector refresh with the live candidate set.
func (h *health) retain(keep map[string]struct{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for addr := range h.m {
		if _, ok := keep[addr]; !ok {
			delete(h.m, addr)
		}
	}
}

// rank buckets a candidate for ordering (lower is preferred):
//
//	0 = alive-and-not-slow, OR unknown (no history) — tried first, in round-robin order
//	1 = alive but slow (EWMA > slowLatency) — demoted below fast/unknown
//	2 = circuit open (recent failure run) — tried last, so recovery is still possible
//
// It deliberately does NOT order class 0 by latency: that would pin traffic to the single
// fastest proxy and kill the relay's IP rotation. Health here means avoid dead/slow, not
// always-pick-fastest.
func (h *health) rank(addr string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.rankLocked(addr, h.now())
}

func (h *health) rankLocked(addr string, now time.Time) int {
	s := h.m[addr]
	if s == nil {
		return 0 // unknown → optimistic, rotate with the healthy ones
	}
	if s.openUntil.After(now) {
		return 2
	}
	if s.hasData && s.ewma > slowLatency {
		return 1
	}
	return 0
}

// order returns a health-classed copy of candidates: alive/unknown first, slow next,
// circuit-open last. It is a STABLE 3-way partition (O(n), one lock acquisition) so
// equal-class candidates keep the caller's round-robin order (IP rotation) untouched —
// replacing the previous per-request O(n log n) sort + per-element lock.
func (h *health) order(candidates []string) []string {
	now := h.now()
	h.mu.Lock()
	defer h.mu.Unlock()
	// b0 is allocated at full capacity so the two follow-up appends reuse its backing
	// array (no realloc): [alive...][slow...][open...].
	b0 := make([]string, 0, len(candidates))
	var b1, b2 []string
	for _, c := range candidates {
		switch h.rankLocked(c, now) {
		case 1:
			b1 = append(b1, c)
		case 2:
			b2 = append(b2, c)
		default:
			b0 = append(b0, c)
		}
	}
	return append(append(b0, b1...), b2...)
}

package relay

import (
	"testing"
	"time"
)

// A run of failures opens the circuit (candidate sinks to the back); a later success
// closes it (candidate returns to the front bucket).
func TestHealthCircuitBreaker(t *testing.T) {
	now := time.Unix(1000, 0)
	h := newHealth()
	h.now = func() time.Time { return now }

	const bad = "http://1.1.1.1:80"
	for i := 0; i < failThreshold; i++ {
		h.report(bad, false, 0)
	}
	if got := h.rank(bad); got != 2 {
		t.Fatalf("after %d failures rank = %d, want 2 (circuit open)", failThreshold, got)
	}

	// order() must push the open-circuit candidate behind a healthy/unknown one.
	got := h.order([]string{bad, "http://2.2.2.2:80"})
	if got[len(got)-1] != bad {
		t.Fatalf("circuit-open candidate not last: %v", got)
	}

	// A success closes the circuit.
	h.report(bad, true, 100*time.Millisecond)
	if got := h.rank(bad); got != 0 {
		t.Fatalf("after success rank = %d, want 0 (closed)", got)
	}
}

// The circuit reopens... err, recovers after the cooldown window elapses even without a
// success: rank returns to 0 once now passes openUntil.
func TestHealthCircuitCooldownExpiry(t *testing.T) {
	now := time.Unix(2000, 0)
	h := newHealth()
	h.now = func() time.Time { return now }
	const bad = "http://1.1.1.1:80"
	for i := 0; i < failThreshold; i++ {
		h.report(bad, false, 0)
	}
	if h.rank(bad) != 2 {
		t.Fatal("expected open circuit")
	}
	now = now.Add(circuitCooldown + time.Second)
	if got := h.rank(bad); got != 0 {
		t.Fatalf("after cooldown rank = %d, want 0", got)
	}
}

// A proven-but-slow proxy is demoted below fast/unknown ones, but fast proxies are NOT
// ordered among themselves (rotation preserved).
func TestHealthSlowDemotionKeepsRotation(t *testing.T) {
	h := newHealth()
	fastA, fastB, slow := "http://a:80", "http://b:80", "http://c:80"
	h.report(fastA, true, 50*time.Millisecond)
	h.report(fastB, true, 60*time.Millisecond)
	h.report(slow, true, (time.Duration(slowLatency)+2)*time.Second)

	got := h.order([]string{fastA, fastB, slow})
	if got[2] != slow {
		t.Fatalf("slow proxy not demoted last: %v", got)
	}
	// fastA before fastB — input order preserved (no latency micro-sorting).
	if got[0] != fastA || got[1] != fastB {
		t.Fatalf("fast proxies reordered (rotation broken): %v", got)
	}
}

// An all-unknown set is returned in the exact input order (pure round-robin upstream).
func TestHealthUnknownPreservesOrder(t *testing.T) {
	h := newHealth()
	in := []string{"http://a:80", "http://b:80", "http://c:80"}
	got := h.order(in)
	for i := range in {
		if got[i] != in[i] {
			t.Fatalf("unknown set reordered at %d: got %v want %v", i, got, in)
		}
	}
}

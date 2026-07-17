package metrics

import "testing"

func TestCountersAndSnapshot(t *testing.T) {
	m := New()
	m.IncRelayHTTP()
	m.IncRelayConnect()
	m.IncRelayConnect()
	m.IncRelaySocks()
	m.IncRelayFailure()
	m.AddUpstream(true)
	m.AddUpstream(false)
	m.AddUpstream(false)

	s := m.Snapshot()
	if s.RelayHTTP != 1 || s.RelayConnect != 2 || s.RelaySocks != 1 || s.RelayFailures != 1 {
		t.Fatalf("request counters wrong: %+v", s)
	}
	if s.UpstreamAttempts != 3 || s.UpstreamFailures != 2 {
		t.Fatalf("upstream counters wrong: %+v", s)
	}
}

// Every method must be safe on a nil *Metrics (components wired without metrics).
func TestNilSafe(t *testing.T) {
	var m *Metrics
	m.IncRelayHTTP()
	m.IncRelayConnect()
	m.IncRelaySocks()
	m.IncRelayFailure()
	m.AddUpstream(true)
	if got := m.Snapshot(); got != (Snapshot{}) {
		t.Fatalf("nil snapshot = %+v, want zero", got)
	}
}

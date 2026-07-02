// Package metrics holds process-wide counters shared between the relay (which increments
// them) and the API (which renders /metrics and /stats). All methods are nil-safe so a
// component wired without metrics simply no-ops.
package metrics

import "sync/atomic"

// Metrics are lock-free counters for relay/SOCKS activity.
type Metrics struct {
	relayHTTP        atomic.Int64
	relayConnect     atomic.Int64
	relaySocks       atomic.Int64
	relayFailures    atomic.Int64
	upstreamAttempts atomic.Int64
	upstreamFailures atomic.Int64
}

// New returns a fresh metrics registry.
func New() *Metrics { return &Metrics{} }

func (m *Metrics) IncRelayHTTP() {
	if m != nil {
		m.relayHTTP.Add(1)
	}
}

func (m *Metrics) IncRelayConnect() {
	if m != nil {
		m.relayConnect.Add(1)
	}
}

func (m *Metrics) IncRelaySocks() {
	if m != nil {
		m.relaySocks.Add(1)
	}
}

func (m *Metrics) IncRelayFailure() {
	if m != nil {
		m.relayFailures.Add(1)
	}
}

// AddUpstream records the outcome of one upstream dial/attempt.
func (m *Metrics) AddUpstream(ok bool) {
	if m == nil {
		return
	}
	m.upstreamAttempts.Add(1)
	if !ok {
		m.upstreamFailures.Add(1)
	}
}

// Snapshot is a point-in-time copy of the counters (for JSON /stats).
type Snapshot struct {
	RelayHTTP        int64 `json:"relay_http_requests"`
	RelayConnect     int64 `json:"relay_connect_requests"`
	RelaySocks       int64 `json:"relay_socks_requests"`
	RelayFailures    int64 `json:"relay_failures"`
	UpstreamAttempts int64 `json:"upstream_attempts"`
	UpstreamFailures int64 `json:"upstream_failures"`
}

// Snapshot reads all counters. A nil receiver yields the zero snapshot.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	return Snapshot{
		RelayHTTP:        m.relayHTTP.Load(),
		RelayConnect:     m.relayConnect.Load(),
		RelaySocks:       m.relaySocks.Load(),
		RelayFailures:    m.relayFailures.Load(),
		UpstreamAttempts: m.upstreamAttempts.Load(),
		UpstreamFailures: m.upstreamFailures.Load(),
	}
}

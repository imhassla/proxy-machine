package relay

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const capabilityLimit = 4096
const capabilityTTL = 5 * time.Minute
const failureTTL = 30 * time.Second

// Capability describes an observation, not a claim of end-to-end anonymity or TLS trust.
// CONNECT observations cannot see the TLS or application protocol inside the byte stream.
type Capability struct {
	Upstream       string    `json:"upstream"`
	Target         string    `json:"target"`
	Operation      string    `json:"operation"`
	Success        bool      `json:"success"`
	Stage          string    `json:"stage"`
	Status         int       `json:"status,omitempty"`
	ObservedAt     time.Time `json:"observed_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	LatencySeconds float64   `json:"latency_seconds"`
}

type capabilityKey struct{ upstream, target, operation string }
type capabilities struct {
	mu      sync.Mutex
	entries map[capabilityKey]Capability
	now     func() time.Time
}

func newCapabilities() *capabilities {
	return &capabilities{entries: make(map[capabilityKey]Capability), now: time.Now}
}

func canonicalTarget(target string) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return strings.ToLower(target)
	}
	return net.JoinHostPort(strings.TrimSuffix(strings.ToLower(host), "."), port)
}

func (c *capabilities) record(upstream, target, operation, stage string, status int, success bool, latency time.Duration) {
	if c == nil {
		return
	}
	// Bound retained bytes as well as entry count, even for oversized client authorities.
	if len(upstream) > 2048 || len(target) > 512 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	k := capabilityKey{upstream, canonicalTarget(target), operation}
	if _, exists := c.entries[k]; !exists && len(c.entries) >= capabilityLimit {
		var oldest capabilityKey
		var at time.Time
		for key, entry := range c.entries {
			if at.IsZero() || entry.ObservedAt.Before(at) {
				oldest, at = key, entry.ObservedAt
			}
		}
		delete(c.entries, oldest)
	}
	ttl := capabilityTTL
	if !success {
		ttl = failureTTL
	}
	c.entries[k] = Capability{upstream, k.target, operation, success, stage, status, now, now.Add(ttl), latency.Seconds()}
}

func (c *capabilities) snapshot() []Capability {
	if c == nil {
		return []Capability{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Capability, 0, len(c.entries))
	for k, entry := range c.entries {
		if !entry.ExpiresAt.After(c.now()) {
			delete(c.entries, k)
			continue
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Upstream != b.Upstream {
			return a.Upstream < b.Upstream
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		return a.Operation < b.Operation
	})
	return out
}

// order prefers fresh compatible observations for stable mode; rotation retains its
// fairness among unknown and successful routes. A destination failure never poisons
// global proxy health. Failed routes are last, allowing recovery after the TTL.
func (c *capabilities) order(candidates []string, target, operation string, stable bool) []string {
	if c == nil {
		return candidates
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var proven, unknown, failed []string
	for _, upstream := range candidates {
		k := capabilityKey{upstream, canonicalTarget(target), operation}
		e, ok := c.entries[k]
		if ok && !e.ExpiresAt.After(c.now()) {
			delete(c.entries, k)
			ok = false
		}
		if ok && !e.Success {
			failed = append(failed, upstream)
		} else if stable && ok {
			proven = append(proven, upstream)
		} else {
			unknown = append(unknown, upstream)
		}
	}
	return append(append(proven, unknown...), failed...)
}

type attemptError struct {
	stage  string
	status int
	err    error
}

func (e *attemptError) Error() string { return e.stage + ": " + e.err.Error() }
func (e *attemptError) Unwrap() error { return e.err }

func failureStage(err error) (string, int) {
	if err == nil {
		return "connect", 0
	}
	var e *attemptError
	if errors.As(err, &e) {
		return e.stage, e.status
	}
	if errors.Is(err, context.Canceled) {
		return "canceled", 0
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return "dial", 0
	}
	return "proxy_handshake", 0
}

// release waits for an already running cancellation callback before the caller clears
// deadlines. This prevents a canceled handshake from poisoning a successful tunnel later.
func interruptHandshake(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()); close(done) })
	var once sync.Once
	return func() {
		once.Do(func() {
			if !stop() {
				<-done
			}
		})
	}
}

func (c *capabilities) usable(upstream, target, operation string) bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[capabilityKey{upstream, canonicalTarget(target), operation}]
	return !ok || !e.ExpiresAt.After(c.now()) || e.Success
}

package checker

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// validationGate reserves capacity for rechecks across harvesting and concurrent
// discovery streams. With a single worker, a waiting recheck gets the next free slot.
type validationGate struct {
	mu                                            sync.Mutex
	total, bulkLimit, active, bulkActive, waiting int
	changed                                       chan struct{}
}

func newValidationGate(total int) *validationGate {
	if total < 1 {
		total = 1
	}
	return &validationGate{total: total, bulkLimit: total, changed: make(chan struct{})}
}

func (g *validationGate) signal() { close(g.changed); g.changed = make(chan struct{}) }
func (g *validationGate) acquire(ctx context.Context, recheck bool) (func(), error) {
	g.mu.Lock()
	if recheck {
		g.waiting++
	}
	for {
		if err := ctx.Err(); err != nil {
			if recheck {
				g.waiting--
				g.signal()
			}
			g.mu.Unlock()
			return nil, err
		}
		if g.active < g.total && (recheck || (g.bulkActive < g.bulkLimit && g.waiting == 0)) {
			g.active++
			if recheck {
				g.waiting--
			} else {
				g.bulkActive++
			}
			g.mu.Unlock()
			return func() {
				g.mu.Lock()
				g.active--
				if !recheck {
					g.bulkActive--
				}
				g.signal()
				g.mu.Unlock()
			}, nil
		}
		changed := g.changed
		g.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-changed:
		}
		g.mu.Lock()
	}
}

type schedulerStats struct {
	pendingCandidates atomic.Int64
	pendingRechecks   atomic.Int64
	lastRecheckLag    atomic.Int64
}

type SchedulingSnapshot struct {
	PendingCandidates     int64   `json:"pending_candidates"`
	PendingRechecks       int64   `json:"pending_rechecks"`
	LastRecheckLagSeconds float64 `json:"last_recheck_lag_seconds"`
}

func (cm *CheckManager) Scheduling() SchedulingSnapshot {
	if cm == nil || cm.scheduling == nil {
		return SchedulingSnapshot{}
	}
	return SchedulingSnapshot{cm.scheduling.pendingCandidates.Load(), cm.scheduling.pendingRechecks.Load(), float64(cm.scheduling.lastRecheckLag.Load()) / float64(time.Second)}
}

// startRechecks has separate adaptive state and cannot wait behind public-list fetching
// or a complete harvest cycle. It shares the global validation budget and database.
func (cm *CheckManager) startRechecks(ctx context.Context) <-chan struct{} {
	cm.gate.reserve()
	cm.skipRechecks = true
	rechecks := New(cm.cfg, cm.db)
	rechecks.owned = cm.owned
	rechecks.IPURLs = cm.IPURLs
	rechecks.TestURLs = cm.TestURLs
	rechecks.skipHarvest = true
	rechecks.gate = cm.gate
	rechecks.scheduling = cm.scheduling
	done := make(chan struct{})
	go func() {
		defer close(done)
		interval := cm.cfg.CheckInterval
		if interval <= 0 {
			interval = time.Minute
		}
		for ctx.Err() == nil {
			rechecks.RunCycle(ctx)
			cm.refreshCacheFromDB()
			t := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}
	}()
	return done
}

func (g *validationGate) reserve() {
	g.mu.Lock()
	defer g.mu.Unlock()
	reserved := g.total / 5
	if reserved < 1 {
		reserved = 1
	}
	g.bulkLimit = g.total - reserved
	if g.bulkLimit < 1 {
		g.bulkLimit = 1
	}
	g.signal()
}

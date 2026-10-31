package node

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

const (
	circuitClosed uint32 = iota
	circuitOpen
	circuitHalfOpen
)

type circuitRules struct {
	failures, recovery, minSamples int
	failureRate                    float64
	maxAge, cooldown, trialTimeout time.Duration
	concurrency, maxRequests       int
}
type circuitBreaker struct {
	rules                       circuitRules
	state                       atomic.Uint32
	mu                          sync.Mutex
	epoch, seen, floor          uint64
	openUntil, trialUntil       time.Time
	inFlight, issued, recovered int
	reason                      string
	changed                     func()
}

func newCircuitBreaker(rules circuitRules, changed func()) *circuitBreaker {
	return &circuitBreaker{rules: rules, changed: changed, reason: "initial"}
}
func (b *circuitBreaker) transition(state uint32, reason string) {
	b.state.Store(state)
	b.epoch++
	b.reason = reason
	b.inFlight, b.issued, b.recovered = 0, 0, 0
	if b.changed != nil {
		b.changed()
	}
}
func (b *circuitBreaker) open(now time.Time, reason string) {
	b.openUntil = now.Add(b.rules.cooldown)
	b.transition(circuitOpen, reason)
}
func (b *circuitBreaker) advance(now time.Time) {
	if b.state.Load() == circuitOpen && !now.Before(b.openUntil) {
		b.trialUntil = now.Add(b.rules.trialTimeout)
		b.transition(circuitHalfOpen, "cooldown_elapsed")
	}
	if b.state.Load() == circuitHalfOpen && !now.Before(b.trialUntil) {
		b.open(now, "trial_timeout")
	}
}

// observe consumes the existing bounded node evidence. It owns no parallel
// traffic/error statistics. Closed-success observations are O(1); only failures
// and initial restoration inspect the existing health window.
func (b *circuitBreaker) observe(h contract.ChannelHealth, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.advance(now)
	if h.Sequence <= b.seen {
		return
	}
	state := b.state.Load()
	if state == circuitOpen {
		b.seen = h.Sequence
		return
	}
	if state == circuitHalfOpen {
		for _, sample := range h.Samples {
			if sample.Sequence <= b.seen || sample.Sequence <= b.floor || sample.At > now.UnixMilli() || now.Sub(time.UnixMilli(sample.At)) > b.rules.maxAge {
				continue
			}
			if sample.Kind == "response" {
				continue
			} // stronger evidence of an already counted TCP connect
			if !sample.OK {
				b.seen = h.Sequence
				b.open(now, "recovery_failure")
				return
			}
			b.recovered++
			if b.recovered >= b.rules.recovery {
				b.floor = h.Sequence
				b.seen = h.Sequence
				b.transition(circuitClosed, "recovered")
				return
			}
		}
		b.seen = h.Sequence
		return
	}
	if b.seen == 0 && h.ConsecutiveSuccesses >= b.rules.recovery {
		b.floor, b.seen = h.Sequence, h.Sequence
		b.reason = "recent_recovery"
		return
	}
	if b.seen > 0 && len(h.Samples) > 0 && h.Samples[len(h.Samples)-1].OK {
		b.seen = h.Sequence
		return
	}
	failures, total, consecutive := 0, 0, 0
	for _, sample := range h.Samples {
		if sample.Kind == "response" || sample.Sequence <= b.floor || sample.At > now.UnixMilli() || now.Sub(time.UnixMilli(sample.At)) > b.rules.maxAge {
			continue
		}
		total++
		if sample.OK {
			consecutive = 0
		} else {
			failures++
			consecutive++
		}
	}
	b.seen = h.Sequence
	if consecutive >= b.rules.failures {
		b.open(now, "consecutive_failures")
	} else if total >= b.rules.minSamples && float64(failures)/float64(total) >= b.rules.failureRate {
		b.open(now, "failure_rate")
	}
}

// tryAcquire has an atomic-only Closed fast path. A Half-open permit reserves
// both concurrency and a finite per-cycle request quota before any network I/O.
func (b *circuitBreaker) tryAcquire(ctx context.Context, now time.Time) (*circuitPermit, bool) {
	if ctx.Err() != nil {
		return nil, false
	}
	if b.state.Load() == circuitClosed {
		return nil, true
	}
	b.mu.Lock()
	b.advance(now)
	if b.state.Load() == circuitClosed {
		b.mu.Unlock()
		return nil, true
	}
	if b.state.Load() != circuitHalfOpen || b.inFlight >= b.rules.concurrency || b.issued >= b.rules.maxRequests {
		b.mu.Unlock()
		return nil, false
	}
	b.inFlight++
	b.issued++
	p := &circuitPermit{breaker: b, epoch: b.epoch}
	deadline := b.trialUntil
	b.mu.Unlock()
	trialCtx, cancel := context.WithDeadline(ctx, deadline)
	p.ctx = trialCtx
	p.cancel = cancel
	p.stop = context.AfterFunc(trialCtx, p.release)
	return p, true
}
func (b *circuitBreaker) snapshot(now time.Time) contract.CircuitStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.advance(now)
	state := "closed"
	if b.state.Load() == circuitOpen {
		state = "open"
	} else if b.state.Load() == circuitHalfOpen {
		state = "half_open"
	}
	v := contract.CircuitStatus{State: state, InFlight: b.inFlight, Issued: b.issued, Recovered: b.recovered, Reason: b.reason}
	if state == "open" {
		v.OpenUntil = b.openUntil.UnixMilli()
	}
	return v
}

type circuitPermit struct {
	breaker *circuitBreaker
	ctx     context.Context
	epoch   uint64
	once    sync.Once
	cancel  context.CancelFunc
	stop    func() bool
}

func (p *circuitPermit) release() {
	if p == nil {
		return
	}
	p.once.Do(func() {
		// The stop/cancel handles are set before the permit is published. An
		// already-cancelled context may run release while registration finishes, so
		// cleanup of those handles is performed by finish rather than this callback.
		p.breaker.mu.Lock()
		if p.breaker.epoch == p.epoch && p.breaker.inFlight > 0 {
			p.breaker.inFlight--
		}
		p.breaker.mu.Unlock()
	})
}
func (p *circuitPermit) finish() {
	if p == nil {
		return
	}
	p.release()
	if p.stop != nil {
		p.stop()
	}
	if p.cancel != nil {
		p.cancel()
	}
}

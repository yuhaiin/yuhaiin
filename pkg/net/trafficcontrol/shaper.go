package trafficcontrol

import (
	"context"
	"errors"
	"math"
	"os"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol/quota"
)

// Direction is from the inbound peer's point of view.
type Direction uint8

const (
	Upload   Direction = iota // inbound peer -> outbound destination
	Download                  // outbound destination -> inbound peer
)

var ErrRateLimited = errors.New("trafficcontrol: datagram rate limit")
var ErrInvalidRate = resource.ErrInvalidRate

// Limiter implements a reservation-based byte token bucket. The virtual
// eligibility timestamp includes already admitted work, so concurrent flows
// cannot collectively bypass a common shaper. No sleeping occurs under mu.
type Limiter struct {
	mu          sync.Mutex
	rate, burst int64
	next        time.Time
	generation  uint64
}

func NewLimiter(bytesPerSecond, burstBytes int64) (*Limiter, error) {
	if err := resource.ValidateRate(Rate{BytesPerSecond: bytesPerSecond, BurstBytes: burstBytes}); err != nil {
		return nil, err
	}
	if bytesPerSecond == 0 {
		return nil, nil
	}
	if burstBytes == 0 {
		// Keep default UDP packets (including large datagrams) admissible at
		// low sustained rates. A smaller explicit burst is permitted, but
		// UDP packets exceeding it will be dropped rather than fragmented.
		burstBytes = 64 << 10
	}
	return &Limiter{rate: bytesPerSecond, burst: burstBytes}, nil
}

func (l *Limiter) duration(n int64) time.Duration {
	// Burst/rate have validated bounds; floating point avoids overflowing
	// nanoseconds for very slow links. Clamp before converting to Duration.
	ns := math.Ceil(float64(n) * float64(time.Second) / float64(l.rate))
	if ns >= float64(math.MaxInt64) {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(ns)
}

func (l *Limiter) nextAt(now time.Time, n int64) time.Time {
	start := now.Add(-l.duration(l.burst))
	if l.next.After(start) {
		start = l.next
	}
	return start.Add(l.duration(n))
}

// Policy carries stable route/inbound identities. Managed policies resolve
// the latest snapshot per operation; standalone policies use explicit scopes.
type Policy struct {
	up, down           [3]*Limiter
	manager            *Manager
	inboundID, routeID string
	identity           *proxyauth.Identity
	usage              *shapingUsage
}

func (p Policy) admitted(d Direction, n int) {
	if p.usage == nil || n <= 0 {
		return
	}
	if p.manager != nil && p.unmanaged(p.manager.active.Load()) {
		return
	}
	if d == Download {
		p.usage.acceptedDown.Add(uint64(n))
	} else {
		p.usage.acceptedUp.Add(uint64(n))
	}
}
func (p Policy) rejected(d Direction) {
	if p.usage == nil {
		return
	}
	if d == Download {
		p.usage.rejectedDown.Add(1)
	} else {
		p.usage.rejectedUp.Add(1)
	}
}

func (p Policy) scopes(d Direction) [3]*Limiter {
	if d == Download {
		return p.down
	}
	return p.up
}

// Lock only selected buckets. A snapshot retry prevents mixing generations;
// updates never require a process-wide packet lock. Rate changes use bucket
// generations, so old operations retry without undoing a newly staged rate.
func (p Policy) lockScopes(d Direction) (scopeSet, <-chan struct{}) {
	if p.manager == nil {
		limits := scopeSet{}
		for i, l := range p.scopes(d) {
			limits.base[i] = l
		}
		lockScopes(limits)
		return limits, nil
	}
	for {
		snapshot := p.manager.active.Load()
		limits := snapshot.scopeSet(p.inboundID, p.routeID, p.identityKey(), d, p.identity != nil)
		lockScopes(limits)
		if p.manager.active.Load() != snapshot {
			unlockScopes(limits)
			continue
		}
		if !scopesCurrent(limits, snapshot.generation) {
			unlockScopes(limits)
			continue
		}
		return limits, snapshot.changed
	}
}

type reservation struct {
	limits scopeSet
	bytes  int
}

func (r reservation) refund(bytes int) {
	if bytes <= 0 {
		return
	}
	lockScopes(r.limits)
	defer unlockScopes(r.limits)
	now := time.Now()
	for i := range r.limits.len() {
		l := r.limits.at(i).limiter
		if l == nil || l.rate == 0 {
			continue
		}
		floor := now.Add(-l.duration(l.burst))
		next := l.next.Add(-l.duration(int64(bytes)))
		if next.Before(floor) {
			next = floor
		}
		l.next = next
	}
}

// AllowDatagram atomically admits every applicable scope without queueing.
func (p Policy) AllowDatagram(d Direction, bytes int) bool {
	if bytes < 0 {
		return false
	}
	if p.manager != nil && p.unmanaged(p.manager.active.Load()) {
		return true
	}
	return p.allowDatagram(d, bytes)
}

func (p Policy) allowDatagram(d Direction, bytes int) bool {
	limits, _ := p.lockScopes(d)
	defer unlockScopes(limits)
	if limits.blocked {
		p.rejected(d)
		return false
	}
	now := time.Now()
	for i := range limits.len() {
		l := limits.at(i).limiter
		if l == nil || l.rate == 0 {
			continue
		}
		if int64(bytes) > l.burst {
			p.rejected(d)
			return false
		}
		next := l.nextAt(now, int64(bytes))
		if next.After(now) {
			p.rejected(d)
			return false
		}
	}
	for i := range limits.len() {
		l := limits.at(i).limiter
		if l != nil && l.rate != 0 {
			l.next = l.nextAt(now, int64(bytes))
		}
	}
	p.admitted(d, bytes)
	return true
}

func (p Policy) WaitBytes(ctx context.Context, d Direction, bytes int) error {
	_, err := p.wait(ctx, d, bytes, false, nil)
	return err
}

// split selects a chunk within current bursts under the admission locks. A
// simultaneous burst reduction cannot strand a previously sized stream write.
func (p Policy) wait(ctx context.Context, d Direction, bytes int, split bool, deadline *streamDeadline) (reservation, error) {
	if bytes <= 0 {
		return reservation{}, nil
	}
	started := time.Now()
	waited := false
	for {
		if err := ctx.Err(); err != nil {
			return reservation{}, err
		}
		limits, changed := p.lockScopes(d)
		if limits.blocked {
			unlockScopes(limits)
			return reservation{}, ErrUnknownResourceIdentity
		}
		n := bytes
		if split {
			n = min(n, 16<<10)
			for i := range limits.len() {
				l := limits.at(i).limiter
				if l != nil && l.rate > 0 {
					n = min(n, int(l.burst))
				}
			}
		}
		now := time.Now()
		if split {
			for i := range limits.len() {
				l := limits.at(i).limiter
				if l != nil && l.rate > 0 && l.nextAt(now, int64(n)).After(now) {
					n = min(n, int(max(int64(1), l.rate/20)))
				}
			}
		}
		deadlineAt, deadlineChanged, deadlineErr := deadline.snapshot()
		if deadlineErr != nil {
			unlockScopes(limits)
			return reservation{}, deadlineErr
		}
		if !deadlineAt.IsZero() && !deadlineAt.After(now) {
			unlockScopes(limits)
			return reservation{}, os.ErrDeadlineExceeded
		}
		ready := now
		valid := true
		for i := range limits.len() {
			l := limits.at(i).limiter
			if l == nil || l.rate == 0 {
				continue
			}
			if int64(n) > l.burst {
				valid = false
				break
			}
			next := l.nextAt(now, int64(n))
			if next.After(ready) {
				ready = next
			}
		}
		if valid && !ready.After(now) {
			for i := range limits.len() {
				l := limits.at(i).limiter
				if l != nil && l.rate != 0 {
					l.next = l.nextAt(now, int64(n))
				}
			}
		}
		unlockScopes(limits)
		if !valid {
			return reservation{}, ErrRateLimited
		}
		if !ready.After(now) {
			r := reservation{limits: limits, bytes: n}
			if err := ctx.Err(); err != nil {
				r.refund(n)
				return reservation{}, err
			}
			p.admitted(d, n)
			if waited && p.usage != nil {
				p.usage.waitNanos.Add(uint64(time.Since(started)))
			}
			return r, nil
		}
		waited = true
		timerAt := ready
		if !deadlineAt.IsZero() && deadlineAt.Before(timerAt) {
			timerAt = deadlineAt
		}
		timer := time.NewTimer(time.Until(timerAt))
		select {
		case <-timer.C:
		case <-changed:
		case <-deadlineChanged:
		case <-ctx.Done():
			timer.Stop()
			return reservation{}, ctx.Err()
		}
		timer.Stop()
	}
}

func (p Policy) Enabled(d Direction) bool {
	if plan, err := p.QuotaPlan(); plan != nil || err != nil {
		return true
	}
	if p.manager != nil {
		limits := p.manager.active.Load().scopeSet(p.inboundID, p.routeID, p.identityKey(), d, p.identity != nil)
		if limits.blocked {
			return true
		}
		for i := range limits.len() {
			if limits.at(i).limiter != nil {
				return true
			}
		}
		return false
	}
	for _, l := range p.scopes(d) {
		if l != nil && l.rate > 0 {
			return true
		}
	}
	return false
}

type ShapedWriter struct {
	deadline  *streamDeadline
	Writer    interface{ Write([]byte) (int, error) }
	Context   context.Context
	Policy    Policy
	Direction Direction
}

func (w ShapedWriter) Write(data []byte) (written int, err error) {
	var ticket quota.Reservation
	for len(data) > 0 {
		n, metered, err := w.Policy.reserveQuota(w.Context, w.Direction, len(data), &ticket, w.deadline)
		if err != nil {
			return written, err
		}
		r, err := w.Policy.wait(w.Context, w.Direction, n, true, w.deadline)
		if err != nil {
			if metered {
				ticket.Commit(0)
			}
			return written, err
		}
		count, writeErr := w.Writer.Write(data[:r.bytes])
		if count < 0 || count > r.bytes {
			if metered {
				ticket.Commit(0)
			}
			r.refund(r.bytes)
			return written, errors.New("trafficcontrol: invalid writer progress")
		}
		if metered {
			ticket.Commit(count)
		}
		r.refund(r.bytes - count)
		written += count
		data = data[count:]
		if writeErr != nil {
			return written, writeErr
		}
		if count != r.bytes {
			return written, errors.New("trafficcontrol: short write")
		}
	}
	return written, nil
}

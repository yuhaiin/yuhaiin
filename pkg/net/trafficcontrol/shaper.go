package trafficcontrol

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"sync"
	"time"
)

// Direction is from the inbound peer's point of view.
type Direction uint8

const (
	Upload   Direction = iota // inbound peer -> outbound destination
	Download                  // outbound destination -> inbound peer
)

var ErrRateLimited = errors.New("trafficcontrol: datagram rate limit")
var ErrInvalidRate = errors.New("trafficcontrol: invalid shaping rate or burst")

const maxShapingRate = int64(1 << 40) // bytes/s
const maxShapingBurst = int64(1 << 30)

// Limiter implements a reservation-based byte token bucket. The virtual
// eligibility timestamp includes already admitted work, so concurrent flows
// cannot collectively bypass a common shaper. No sleeping occurs under mu.
type Limiter struct {
	mu          sync.Mutex
	rate, burst int64
	next        time.Time
}

func NewLimiter(bytesPerSecond, burstBytes int64) (*Limiter, error) {
	if bytesPerSecond < 0 || burstBytes < 0 || bytesPerSecond > maxShapingRate || burstBytes > maxShapingBurst {
		return nil, ErrInvalidRate
	}
	if bytesPerSecond == 0 {
		if burstBytes != 0 {
			return nil, fmt.Errorf("%w: unlimited shaper cannot have a burst", ErrInvalidRate)
		}
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
	usage              *shapingUsage
}

func (p Policy) admitted(d Direction, n int) {
	if p.usage == nil || n <= 0 {
		return
	}
	if p.manager != nil && !p.manager.active.Load().config.Enabled {
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

// All managed operations take the stable global lock before loading their
// snapshot. Activation holds both direction locks, so no operation can observe
// a partially updated hierarchy. Refunds retain the exact admitted scopes.
func (p Policy) lockScopes(d Direction) (limits [3]*Limiter, changed <-chan struct{}) {
	if p.manager == nil {
		limits = p.scopes(d)
		lockScopes(limits, 0)
		return
	}
	root := p.manager.global.up
	if d == Download {
		root = p.manager.global.down
	}
	root.mu.Lock()
	s := p.manager.active.Load()
	changed = s.changed
	if !s.config.Enabled {
		root.mu.Unlock()
		return
	}
	up, down, _, _ := s.scopes(p.inboundID, p.routeID)
	limits = up
	if d == Download {
		limits = down
	}
	lockScopes(limits, 1)
	return
}
func lockScopes(limits [3]*Limiter, start int) {
	for _, l := range limits[start:] {
		if l != nil {
			l.mu.Lock()
		}
	}
}
func unlockScopes(limits [3]*Limiter) {
	for i := len(limits) - 1; i >= 0; i-- {
		if limits[i] != nil {
			limits[i].mu.Unlock()
		}
	}
}

type reservation struct {
	limits [3]*Limiter
	bytes  int
}

func (r reservation) refund(bytes int) {
	if bytes <= 0 {
		return
	}
	lockScopes(r.limits, 0)
	defer unlockScopes(r.limits)
	now := time.Now()
	for _, l := range r.limits {
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
	if p.manager != nil && !p.manager.active.Load().config.Enabled {
		return true
	}
	limits, _ := p.lockScopes(d)
	defer unlockScopes(limits)
	now := time.Now()
	var next [3]time.Time
	for i, l := range limits {
		if l == nil || l.rate == 0 {
			continue
		}
		if int64(bytes) > l.burst {
			p.rejected(d)
			return false
		}
		next[i] = l.nextAt(now, int64(bytes))
		if next[i].After(now) {
			p.rejected(d)
			return false
		}
	}
	for i, l := range limits {
		if l != nil && l.rate != 0 {
			l.next = next[i]
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
		n := bytes
		if split {
			n = min(n, 16<<10)
			for _, l := range limits {
				if l != nil && l.rate > 0 {
					n = min(n, int(l.burst))
				}
			}
		}
		now := time.Now()
		if split {
			for _, l := range limits {
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
		var next [3]time.Time
		valid := true
		for i, l := range limits {
			if l == nil || l.rate == 0 {
				continue
			}
			if int64(n) > l.burst {
				valid = false
				break
			}
			next[i] = l.nextAt(now, int64(n))
			if next[i].After(ready) {
				ready = next[i]
			}
		}
		if valid && !ready.After(now) {
			for i, l := range limits {
				if l != nil && l.rate != 0 {
					l.next = next[i]
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
	if p.manager != nil {
		_, _, up, down := p.manager.active.Load().scopes(p.inboundID, p.routeID)
		if d == Download {
			return down
		}
		return up
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
	for len(data) > 0 {
		r, err := w.Policy.wait(w.Context, w.Direction, len(data), true, w.deadline)
		if err != nil {
			return written, err
		}
		count, writeErr := w.Writer.Write(data[:r.bytes])
		if count < 0 || count > r.bytes {
			r.refund(r.bytes)
			return written, errors.New("trafficcontrol: invalid writer progress")
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

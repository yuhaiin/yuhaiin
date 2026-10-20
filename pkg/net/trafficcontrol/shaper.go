package trafficcontrol

import (
	"context"
	"errors"
	"fmt"
	"math"
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

// Policy is a per-flow immutable reference to at most four shared scopes.
// Every scope has independent up/down shaping state. The snapshot that
// created these pointers remains alive for the lifetime of a flow.
type Policy struct {
	up, down [4]*Limiter
}

func (p Policy) scopes(direction Direction) [4]*Limiter {
	if direction == Download {
		return p.down
	}
	return p.up
}

// AllowDatagram performs all-or-nothing token admission under the locks of
// every applicable scope. UDP never sleeps and never accumulates a backlog.
// A rejected local quota cannot steal credits from shared parent scopes.
func (p Policy) AllowDatagram(direction Direction, bytes int) bool {
	if bytes < 0 {
		return false
	}
	limits := p.scopes(direction)
	for _, l := range limits {
		if l != nil {
			l.mu.Lock()
		}
	}
	defer func() {
		for i := len(limits) - 1; i >= 0; i-- {
			if limits[i] != nil {
				limits[i].mu.Unlock()
			}
		}
	}()
	now := time.Now()
	var next [4]time.Time
	for i, l := range limits {
		if l == nil {
			continue
		}
		// Datagram admission cannot wait for a future slot, or request
		// more bytes than a bucket can hold in one instant.
		if int64(bytes) > l.burst {
			return false
		}
		next[i] = l.nextAt(now, int64(bytes))
		if next[i].After(now) {
			return false
		}
	}
	for i, l := range limits {
		if l != nil {
			l.next = next[i]
		}
	}
	return true
}

// WaitBytes reserves pacing time across all policy scopes. It retains only
// the caller's bounded buffer while waiting, never another queued copy.
// A cancelled reservation is not automatically reclaimed if a concurrent
// reservation depends on its virtual timestamp: this trades some temporary
// underutilization for hard non-oversubscription.
func (p Policy) WaitBytes(ctx context.Context, direction Direction, bytes int) error {
	if bytes <= 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	limits := p.scopes(direction)
	for _, l := range limits {
		if l != nil {
			l.mu.Lock()
		}
	}
	now := time.Now()
	deadline := now
	for _, l := range limits {
		if l == nil {
			continue
		}
		next := l.nextAt(now, int64(bytes))
		l.next = next
		if next.After(deadline) {
			deadline = next
		}
	}
	for i := len(limits) - 1; i >= 0; i-- {
		if limits[i] != nil {
			limits[i].mu.Unlock()
		}
	}
	wait := time.Until(deadline)
	if wait <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p Policy) Enabled(direction Direction) bool {
	for _, l := range p.scopes(direction) {
		if l != nil {
			return true
		}
	}
	return false
}

// ShapedWriter bounds each admitted read/write chunk. After one chunk is
// read, the write blocks until its byte reservation becomes eligible, so TCP
// backpressure propagates without accumulating an unbounded queue.
type ShapedWriter struct {
	Writer    interface{ Write([]byte) (int, error) }
	Context   context.Context
	Policy    Policy
	Direction Direction
}

// Write respects io.Writer's partial-write contract. It must not acknowledge
// bytes to the caller until the underlying transport has accepted them.
func (w ShapedWriter) Write(data []byte) (written int, err error) {
	for len(data) > 0 {
		n := min(len(data), 16<<10)
		// Bound the reservation by each shaper's burst where possible;
		// very-low-rate configurations still work, although throughput will
		// be correspondingly small.
		for _, lim := range w.Policy.scopes(w.Direction) {
			if lim != nil && int64(n) > lim.burst {
				n = int(lim.burst)
			}
		}
		if err = w.Policy.WaitBytes(w.Context, w.Direction, n); err != nil {
			return written, err
		}
		count, writeErr := w.Writer.Write(data[:n])
		if count < 0 || count > n {
			return written, errors.New("trafficcontrol: invalid writer progress")
		}
		written += count
		data = data[count:]
		if writeErr != nil {
			return written, writeErr
		}
		if count != n {
			return written, errors.New("trafficcontrol: short write")
		}
	}
	return written, nil
}

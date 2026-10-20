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
	usage    *shapingUsage
}

func (p Policy) admitted(d Direction, n int) {
	if p.usage == nil || n <= 0 {
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

func (p Policy) scopes(direction Direction) [4]*Limiter {
	if direction == Download {
		return p.down
	}
	return p.up
}

// refundBytes returns unused bytes from a reservation-based stream write.
// Reservations are fungible within each shared bucket, so moving its virtual
// eligibility time back by the unused byte duration preserves aggregate
// accounting even when other writers reserved bytes in the meantime.
func (p Policy) refundBytes(direction Direction, bytes int) {
	if bytes <= 0 {
		return
	}
	limits := p.scopes(direction)
	for _, l := range limits {
		if l != nil {
			l.mu.Lock()
		}
	}
	now := time.Now()
	for _, l := range limits {
		if l == nil {
			continue
		}
		floor := now.Add(-l.duration(l.burst))
		next := l.next.Add(-l.duration(int64(bytes)))
		if next.Before(floor) {
			next = floor
		}
		l.next = next
	}
	for i := len(limits) - 1; i >= 0; i-- {
		if limits[i] != nil {
			limits[i].mu.Unlock()
		}
	}
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
			p.rejected(direction)
			return false
		}
		next[i] = l.nextAt(now, int64(bytes))
		if next[i].After(now) {
			p.rejected(direction)
			return false
		}
	}
	for i, l := range limits {
		if l != nil {
			l.next = next[i]
		}
	}
	p.admitted(direction, bytes)
	return true
}

// WaitBytes waits until every applicable scope can admit the bytes, then
// atomically charges all of them. Waiting does not reserve future tokens, so
// context cancellation leaves no virtual-time debt that would starve other
// healthy streams. TCP backpressure keeps only the current write buffer live.
func (p Policy) WaitBytes(ctx context.Context, direction Direction, bytes int) error {
	if bytes <= 0 {
		return nil
	}
	limits := p.scopes(direction)
	started := time.Now()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, l := range limits {
			if l != nil {
				l.mu.Lock()
			}
		}
		now := time.Now()
		ready := now
		var next [4]time.Time
		valid := true
		for i, l := range limits {
			if l == nil {
				continue
			}
			if int64(bytes) > l.burst {
				valid = false
				break
			}
			next[i] = l.nextAt(now, int64(bytes))
			if next[i].After(ready) {
				ready = next[i]
			}
		}
		if valid && !ready.After(now) {
			for i, l := range limits {
				if l != nil {
					l.next = next[i]
				}
			}
		}
		for i := len(limits) - 1; i >= 0; i-- {
			if limits[i] != nil {
				limits[i].mu.Unlock()
			}
		}
		if !valid {
			return ErrRateLimited
		}
		if !ready.After(now) {
			if err := ctx.Err(); err != nil {
				return err
			}
			p.admitted(direction, bytes)
			if p.usage != nil {
				p.usage.waitNanos.Add(uint64(time.Since(started)))
			}
			return nil
		}
		timer := time.NewTimer(time.Until(ready))
		select {
		case <-timer.C:
			timer.Stop()
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
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
		if count < n {
			w.Policy.refundBytes(w.Direction, n-count)
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

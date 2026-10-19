package trafficcontrol

import (
	"container/list"
	"math"
	"sync"
	"time"
)

// FairConfig controls a byte-based DRR queue with CoDel-style sojourn control.
// Packet and byte caps are strict, independent bounds. Time parameters use a
// monotonic time.Time when supplied by callers.
type FairConfig struct {
	MaxPackets int
	MaxBytes   int64
	Quantum    int
	Target     time.Duration
	Interval   time.Duration
}

type FairStats struct {
	Packets, Bytes       int64
	Flows                int
	Rejected, DroppedAQM uint64
	Dequeued             uint64
	MaxSojourn           time.Duration
}

type queued[T any] struct {
	value T
	bytes int
	at    time.Time
}

type fairFlow[T any] struct {
	key        uint64
	packets    []queued[T]
	head       int
	deficit    int
	firstAbove time.Time
	dropping   bool
	dropCount  uint64
	dropNext   time.Time
	element    *list.Element
}

// FairQueue uses a bounded active-flow map and O(1) insertion. Pop applies
// byte-aware deficit round robin; excess sojourn triggers CoDel-style drops.
// It owns admitted values until Pop or Drain returns them to the caller.
// Dequeue order within each flow is always FIFO (excluding AQM drops).
type FairQueue[T any] struct {
	mu                          sync.Mutex
	cfg                         FairConfig
	flows                       map[uint64]*fairFlow[T]
	active                      list.List
	count                       int64
	bytes                       int64
	rejected, dropped, dequeued uint64
	maxSojourn                  time.Duration
	notify                      chan struct{}
}

func NewFairQueue[T any](c FairConfig) *FairQueue[T] {
	if c.MaxPackets <= 0 || c.MaxBytes <= 0 {
		panic("trafficcontrol: fair queue requires positive packet and byte bounds")
	}
	if c.Quantum <= 0 {
		c.Quantum = 1514
	}
	if c.Target <= 0 {
		c.Target = 5 * time.Millisecond
	}
	if c.Interval <= 0 {
		c.Interval = 100 * time.Millisecond
	}
	return &FairQueue[T]{cfg: c, flows: make(map[uint64]*fairFlow[T]), notify: make(chan struct{}, 1)}
}

func (q *FairQueue[T]) Notify() <-chan struct{} { return q.notify }

func (q *FairQueue[T]) HasCapacity() bool {
	q.mu.Lock()
	ok := q.count < int64(q.cfg.MaxPackets) && q.bytes < q.cfg.MaxBytes
	q.mu.Unlock()
	return ok
}

func (q *FairQueue[T]) Push(key uint64, size int, value T, at time.Time) bool {
	if size <= 0 {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.count >= int64(q.cfg.MaxPackets) || int64(size) > q.cfg.MaxBytes-q.bytes {
		q.rejected++
		return false
	}
	f := q.flows[key]
	if f == nil {
		f = &fairFlow[T]{key: key}
		f.element = q.active.PushBack(f)
		q.flows[key] = f
	}
	f.packets = append(f.packets, queued[T]{value: value, bytes: size, at: at})
	q.count++
	q.bytes += int64(size)
	select {
	case q.notify <- struct{}{}:
	default:
	}
	return true
}

func (q *FairQueue[T]) remove(f *fairFlow[T]) queued[T] {
	p := f.packets[f.head]
	var zero queued[T]
	f.packets[f.head] = zero
	f.head++
	q.count--
	q.bytes -= int64(p.bytes)
	if f.head == len(f.packets) {
		q.active.Remove(f.element)
		delete(q.flows, f.key)
	} else if f.head > 64 && f.head >= len(f.packets)/2 {
		// Shrink idle array tails; retained metadata is never proportional to
		// an old traffic burst after the backlog has drained.
		next := make([]queued[T], len(f.packets)-f.head)
		copy(next, f.packets[f.head:])
		f.packets, f.head = next, 0
	}
	return p
}

// Pop returns one scheduled packet and any AQM-discarded packets. The caller
// MUST release all returned drop values, even if no packet is returned.
// Never release pool-backed packet data while holding the queue mutex.
func (q *FairQueue[T]) Pop(now time.Time) (value T, ok bool, dropped []T) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for q.active.Len() != 0 {
		f := q.active.Front().Value.(*fairFlow[T])
		p := f.packets[f.head]
		if f.deficit < p.bytes {
			f.deficit += q.cfg.Quantum
			q.active.MoveToBack(f.element)
			continue
		}
		delay := now.Sub(p.at)
		if delay < 0 {
			delay = 0
		}
		if delay > q.maxSojourn {
			q.maxSojourn = delay
		}
		// CoDel: the delay must remain above target for an interval before
		// entering dropping state. Once dropping, schedule subsequent drops
		// using interval / sqrt(drop count). The inverse square root is only
		// evaluated on a drop, not on the ordinary dequeue fast path.
		congested := delay > q.cfg.Target && q.bytes > int64(q.cfg.Quantum) && q.count > 1
		if !congested {
			f.firstAbove = time.Time{}
			f.dropping = false
			f.dropCount = 0
		} else if f.firstAbove.IsZero() {
			f.firstAbove = now.Add(q.cfg.Interval)
		}
		shouldDrop := congested && (f.dropping && !now.Before(f.dropNext) ||
			!f.dropping && !f.firstAbove.IsZero() && !now.Before(f.firstAbove))
		if shouldDrop {
			if !f.dropping {
				f.dropping = true
				f.dropCount = 0
			}
			f.dropCount++
			f.dropNext = now.Add(time.Duration(float64(q.cfg.Interval) / math.Sqrt(float64(f.dropCount))))
			old := q.remove(f)
			q.dropped++
			dropped = append(dropped, old.value)
			continue
		}
		chosen := q.remove(f)
		q.dequeued++
		f.deficit -= chosen.bytes
		if q.flows[f.key] != nil && f.deficit < f.packets[f.head].bytes {
			q.active.MoveToBack(f.element)
		}
		return chosen.value, true, dropped
	}
	return value, false, dropped
}

// Drain transfers all remaining leases to the caller on shutdown.
func (q *FairQueue[T]) Drain() []T {
	q.mu.Lock()
	defer q.mu.Unlock()
	all := make([]T, 0, q.count)
	for q.active.Len() != 0 {
		f := q.active.Front().Value.(*fairFlow[T])
		all = append(all, q.remove(f).value)
	}
	return all
}

func (q *FairQueue[T]) Stats() FairStats {
	q.mu.Lock()
	defer q.mu.Unlock()
	return FairStats{
		Packets: q.count, Bytes: q.bytes, Flows: len(q.flows),
		Rejected: q.rejected, DroppedAQM: q.dropped,
		Dequeued: q.dequeued, MaxSojourn: q.maxSojourn,
	}
}

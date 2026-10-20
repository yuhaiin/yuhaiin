package trafficcontrol

import (
	"sync"
	"sync/atomic"
	"time"
)

type SchedulerMode string

const (
	SchedulerFIFO SchedulerMode = "fifo"
	SchedulerFair SchedulerMode = "fq_codel"
)

type Classification struct {
	Host, Flow uint64
	Weight     int
}

// OutputQueue is the ownership contract at a contended packet writer. Enqueue
// takes ownership only on success; Dequeue/Drain transfer it back. Any packets
// shed by admission or AQM are released by the supplied callback outside locks.
type OutputQueue[T any] interface {
	Enqueue(T) bool
	Dequeue(done <-chan struct{}, wait bool) (T, bool)
	HasCapacity(bytes int) bool
	Drain() []T
	Stats() FairStats
}
type OutputOptions[T any] struct {
	Limits   FairConfig
	Mode     SchedulerMode
	Size     func(T) int
	Classify func(T) Classification
	Release  func(T)
}

func NewOutputQueue[T any](o OutputOptions[T]) OutputQueue[T] {
	if o.Mode == SchedulerFIFO {
		if o.Limits.MaxPackets <= 0 || o.Limits.MaxBytes <= 0 {
			panic("trafficcontrol: invalid output bounds")
		}
		return &fifoOutput[T]{values: make(chan T, o.Limits.MaxPackets), maxBytes: o.Limits.MaxBytes, size: o.Size}
	}
	return &fairOutput[T]{queue: NewGroupedFairQueue[T](o.Limits), options: o}
}

// A lone packet needs no classification or flow descriptor. Only contention
// promotes that packet into the fair domain, preserving its original sojourn.
// The notification is drained under the ownership lock when the queue empties,
// avoiding stale wakeups and repeated clock reads between sparse packets.
type fairOutput[T any] struct {
	mu         sync.Mutex
	queue      *GroupedFairQueue[T]
	options    OutputOptions[T]
	single     T
	singleAt   time.Time
	singleSize int
	hasSingle  bool
}

func (q *fairOutput[T]) Enqueue(v T) bool {
	size := q.options.Size(v)
	q.mu.Lock()
	if size <= 0 || int64(size) > q.queue.cfg.MaxBytes {
		q.queue.rejected++
		q.mu.Unlock()
		return false
	}
	if !q.hasSingle && q.queue.packets == 0 {
		q.single, q.singleSize, q.singleAt, q.hasSingle = v, size, time.Now(), true
		select {
		case q.queue.notify <- struct{}{}:
		default:
		}
		q.mu.Unlock()
		return true
	}
	if q.hasSingle {
		c := q.options.Classify(q.single)
		q.queue.push(c.Host, c.Flow, q.singleSize, q.single, q.singleAt, c.Weight)
		var zero T
		q.single = zero
		q.hasSingle = false
	}
	c := q.options.Classify(v)
	accepted, drops := q.queue.admit(c.Host, c.Flow, size, v, time.Now(), c.Weight)
	q.mu.Unlock()
	for _, drop := range drops {
		q.options.Release(drop)
	}
	return accepted
}
func (q *fairOutput[T]) Dequeue(done <-chan struct{}, wait bool) (value T, ok bool) {
	for {
		select {
		case <-done:
			return value, false
		default:
		}
		q.mu.Lock()
		var drops []T
		switch {
		case q.hasSingle:
			value, ok = q.single, true
			var zero T
			q.single = zero
			q.hasSingle = false
			delay := time.Since(q.singleAt)
			if delay > q.queue.maxSojourn {
				q.queue.maxSojourn = delay
			}
			q.queue.dequeued++
		case q.queue.packets > 0:
			value, ok, drops = q.queue.pop(time.Now())
		}
		if q.queue.packets == 0 && !q.hasSingle {
			select {
			case <-q.queue.notify:
			default:
			}
		}
		q.mu.Unlock()
		for _, drop := range drops {
			q.options.Release(drop)
		}
		if ok {
			return value, true
		}
		if !wait {
			return value, false
		}
		select {
		case <-done:
			return value, false
		case <-q.queue.notify:
		}
	}
}
func (q *fairOutput[T]) HasCapacity(bytes int) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.hasSingle {
		return q.queue.cfg.MaxPackets > 1 && int64(bytes) <= q.queue.flowByteLimit()-int64(q.singleSize)
	}
	return q.queue.hasCapacity(bytes)
}
func (q *fairOutput[T]) Drain() []T {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.queue.drain()
	if q.hasSingle {
		out = append(out, q.single)
		var zero T
		q.single = zero
		q.hasSingle = false
	}
	return out
}
func (q *fairOutput[T]) Stats() FairStats {
	q.mu.Lock()
	defer q.mu.Unlock()
	stats := q.queue.stats()
	if q.hasSingle {
		stats.Packets++
		stats.Bytes += int64(q.singleSize)
		stats.Flows++
	}
	return stats
}

type fifoOutput[T any] struct {
	values             chan T
	size               func(T) int
	maxBytes           int64
	bytes              atomic.Int64
	rejected, dequeued atomic.Uint64
}

func (q *fifoOutput[T]) Enqueue(v T) bool {
	size := int64(q.size(v))
	if !reserve(&q.bytes, size, q.maxBytes) {
		q.rejected.Add(1)
		return false
	}
	select {
	case q.values <- v:
		return true
	default:
		q.bytes.Add(-size)
		q.rejected.Add(1)
		return false
	}
}
func (q *fifoOutput[T]) Dequeue(done <-chan struct{}, wait bool) (value T, ok bool) {
	if wait {
		select {
		case <-done:
			return value, false
		case value = <-q.values:
			ok = true
		}
	} else {
		select {
		case value = <-q.values:
			ok = true
		default:
			return value, false
		}
	}
	q.bytes.Add(-int64(q.size(value)))
	q.dequeued.Add(1)
	return
}
func (q *fifoOutput[T]) HasCapacity(bytes int) bool {
	return len(q.values) < cap(q.values) && int64(bytes) <= q.maxBytes-q.bytes.Load()
}
func (q *fifoOutput[T]) Drain() []T {
	out := make([]T, 0, len(q.values))
	for {
		v, ok := q.Dequeue(nil, false)
		if !ok {
			return out
		}
		out = append(out, v)
	}
}
func (q *fifoOutput[T]) Stats() FairStats {
	return FairStats{Packets: int64(len(q.values)), Bytes: q.bytes.Load(), Rejected: q.rejected.Load(), Dequeued: q.dequeued.Load()}
}

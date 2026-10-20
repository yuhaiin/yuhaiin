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
	Dequeue(wait bool) (T, bool)
	// DequeueBatch waits only for the first packet, then drains available work.
	// A bounded batch shares one scheduling timestamp and ownership lock.
	DequeueBatch(dst []T, wait bool) int
	HasCapacity(bytes int) bool
	// Close rejects new work and wakes blocked readers; Drain returns owned work.
	Close()
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
		return &fifoOutput[T]{done: make(chan struct{}), values: make(chan T, o.Limits.MaxPackets), maxBytes: o.Limits.MaxBytes, size: o.Size}
	}
	q := &fairOutput[T]{queue: NewGroupedFairQueue[T](o.Limits), options: o}
	q.queue.notify = nil // The adapter's condition variable owns wakeups.
	q.ready.L = &q.mu
	return q
}

// A lone packet needs no classification or flow descriptor. Only contention
// promotes that packet into the fair domain, preserving its original sojourn.
// Queue readiness and Close share the ownership lock, so a writer wakes
// holding that lock without a separate notification channel or a second lock.
type fairOutput[T any] struct {
	mu         sync.Mutex
	ready      sync.Cond
	closed     bool
	queue      *GroupedFairQueue[T]
	options    OutputOptions[T]
	single     T
	singleAt   time.Duration
	singleSize int
	hasSingle  bool
}

func (q *fairOutput[T]) Enqueue(v T) bool {
	size := q.options.Size(v)
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return false
	}
	if size <= 0 || int64(size) > q.queue.cfg.MaxBytes {
		q.queue.rejected++
		q.mu.Unlock()
		return false
	}
	if !q.hasSingle && q.queue.packets == 0 {
		q.single, q.singleSize, q.singleAt, q.hasSingle = v, size, queueNow(), true
		q.ready.Signal()
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
	accepted, drops := q.queue.admit(c.Host, c.Flow, size, v, queueNow(), c.Weight)
	// A writer cannot be asleep while this queue was already nonempty.
	// Dequeue hands readiness to another reader if it leaves a backlog.
	q.mu.Unlock()
	for _, drop := range drops {
		q.options.Release(drop)
	}
	return accepted
}
func (q *fairOutput[T]) Dequeue(wait bool) (value T, ok bool) {
	var dst [1]T
	n := q.DequeueBatch(dst[:], wait)
	return dst[0], n != 0
}
func (q *fairOutput[T]) DequeueBatch(dst []T, wait bool) int {
	if len(dst) == 0 {
		return 0
	}
	q.mu.Lock()
	for !q.closed && !q.hasSingle && q.queue.packets == 0 && wait {
		q.ready.Wait()
	}
	for {
		if q.closed {
			q.mu.Unlock()
			return 0
		}
		if q.hasSingle {
			dst[0] = q.single
			var zero T
			q.single = zero
			q.hasSingle = false
			q.queue.maxSojourn = max(q.queue.maxSojourn, queueDelay(queueNow(), q.singleAt))
			q.queue.dequeued++
			q.mu.Unlock()
			return 1
		}
		var drops []T
		n := 0
		if q.queue.packets > 0 {
			now := queueNow()
			for n < len(dst) && q.queue.packets > 0 {
				v, ok, discarded := q.queue.pop(now)
				drops = append(drops, discarded...)
				if !ok {
					break
				}
				dst[n] = v
				n++
			}
		}
		if q.queue.packets > 0 {
			q.ready.Signal()
		}
		q.mu.Unlock()
		for _, drop := range drops {
			q.options.Release(drop)
		}
		if n > 0 || !wait {
			return n
		}
		q.mu.Lock()
		for !q.closed && !q.hasSingle && q.queue.packets == 0 {
			q.ready.Wait()
		}
	}
}
func (q *fairOutput[T]) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.ready.Broadcast()
}

func (q *fairOutput[T]) HasCapacity(bytes int) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return false
	}
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
	admission          sync.Mutex
	closed             atomic.Bool
	done               chan struct{}
	values             chan T
	size               func(T) int
	maxBytes           int64
	bytes              atomic.Int64
	rejected, dequeued atomic.Uint64
}

func (q *fifoOutput[T]) Enqueue(v T) bool {
	if q.closed.Load() {
		return false
	}
	size := int64(q.size(v))
	q.admission.Lock()
	defer q.admission.Unlock()
	if q.closed.Load() {
		return false
	}
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
func (q *fifoOutput[T]) Dequeue(wait bool) (value T, ok bool) {
	if q.closed.Load() {
		return value, false
	}
	if wait {
		select {
		case <-q.done:
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
func (q *fifoOutput[T]) DequeueBatch(dst []T, wait bool) int {
	for i := range dst {
		v, ok := q.Dequeue(wait && i == 0)
		if !ok {
			return i
		}
		dst[i] = v
	}
	return len(dst)
}
func (q *fifoOutput[T]) Close() {
	q.admission.Lock()
	defer q.admission.Unlock()
	if !q.closed.Load() {
		q.closed.Store(true)
		close(q.done)
	}
}

func (q *fifoOutput[T]) HasCapacity(bytes int) bool {
	return !q.closed.Load() && len(q.values) < cap(q.values) && int64(bytes) <= q.maxBytes-q.bytes.Load()
}
func (q *fifoOutput[T]) Drain() []T {
	out := make([]T, 0, len(q.values))
	for {
		var v T
		select {
		case v = <-q.values:
			q.bytes.Add(-int64(q.size(v)))
			q.dequeued.Add(1)
		default:
			return out
		}
		out = append(out, v)
	}
}
func (q *fifoOutput[T]) Stats() FairStats {
	return FairStats{Packets: int64(len(q.values)), Bytes: q.bytes.Load(), Rejected: q.rejected.Load(), Dequeued: q.dequeued.Load()}
}

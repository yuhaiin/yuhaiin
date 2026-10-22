package trafficcontrol

import (
	"math"
	"sync"
	"time"
)

// FairConfig controls a byte-based DRR queue with CoDel-style sojourn control.
// Packet and byte caps are strict independent bounds.
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
	DroppedOverload      uint64
	Dequeued             uint64
	MaxSojourn           int64 // Maximum observed queue sojourn in nanoseconds.
}

type queued[T any] struct {
	value  T
	bytes  int
	weight int
	at     time.Duration
}

type fairFlow[T any] struct {
	key           uint64
	bytes         int64
	packets       []queued[T]
	head          int
	deficit       int
	firstAbove    time.Duration
	firstAboveSet bool
	dropping      bool
	dropCount     uint64
	dropNext      time.Duration
	prev, next    *fairFlow[T]
}

// FairQueue bounds active flow descriptors, retained packets and bytes.
// Metadata uses intrusive links and a descriptor pool: a high rate of
// short-lived flows does not allocate a container/list element per packet.
// Values belong to this queue until popped, dropped or drained.
type FairQueue[T any] struct {
	mu                          sync.Mutex
	cfg                         FairConfig
	flows                       map[uint64]*fairFlow[T]
	head, tail                  *fairFlow[T]
	recent                      *fairFlow[T]
	pool                        *sync.Pool
	count, bytes                int64
	rejected, dropped, dequeued uint64
	maxSojourn                  time.Duration
	maxFlows                    int
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
	q := &FairQueue[T]{cfg: c, flows: make(map[uint64]*fairFlow[T]), notify: make(chan struct{}, 1), pool: &sync.Pool{New: func() any { return new(fairFlow[T]) }}}
	return q
}

func (q *FairQueue[T]) Notify() <-chan struct{} { return q.notify }

func (q *FairQueue[T]) HasCapacity() bool {
	q.mu.Lock()
	ok := q.count < int64(q.cfg.MaxPackets) && q.bytes < q.cfg.MaxBytes
	q.mu.Unlock()
	return ok
}

func (q *FairQueue[T]) appendFlow(f *fairFlow[T]) {
	f.prev = q.tail
	f.next = nil
	if q.tail == nil {
		q.head = f
	} else {
		q.tail.next = f
	}
	q.tail = f
}

func (q *FairQueue[T]) unlinkFlow(f *fairFlow[T]) {
	if f.prev == nil {
		q.head = f.next
	} else {
		f.prev.next = f.next
	}
	if f.next == nil {
		q.tail = f.prev
	} else {
		f.next.prev = f.prev
	}
	f.prev, f.next = nil, nil
}

func (q *FairQueue[T]) moveToBack(f *fairFlow[T]) {
	if q.tail == f {
		return
	}
	q.unlinkFlow(f)
	q.appendFlow(f)
}

// Repeated packets of an active flow need no map lookup. Retirement clears
// the hint before recycling its descriptor; the map remains authoritative.
func (q *FairQueue[T]) flow(key uint64) *fairFlow[T] {
	if f := q.recent; f != nil && f.key == key {
		return f
	}
	q.recent = q.flows[key]
	return q.recent
}

func (q *FairQueue[T]) Push(key uint64, size int, value T, at time.Time) bool {
	return q.PushWeighted(key, size, value, at, 1)
}

// PushWeighted provides bounded service differentiation without strict
// priority starvation. A weight is clamped to [1,4] and applies per flow.
func (q *FairQueue[T]) PushWeighted(key uint64, size int, value T, at time.Time, weight int) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.pushWeighted(key, size, value, queueTime(at), weight)
}

// The grouped scheduler holds its one outer lock and calls these core methods
// directly. Standalone queues retain the same public synchronization boundary.
func (q *FairQueue[T]) pushWeighted(key uint64, size int, value T, at time.Duration, weight int) bool {
	if size <= 0 {
		return false
	}
	if q.count >= int64(q.cfg.MaxPackets) || int64(size) > q.cfg.MaxBytes-q.bytes {
		q.rejected++
		return false
	}
	f := q.flow(key)
	if f == nil {
		f = q.pool.Get().(*fairFlow[T])
		f.key = key
		q.appendFlow(f)
		q.flows[key] = f
		q.recent = f
		q.maxFlows = max(q.maxFlows, len(q.flows))
	}
	q.appendPacket(f, size, value, at, weight)
	return true
}

// Admission is already checked by pushWeighted or the aggregate scheduler.
func (q *FairQueue[T]) appendPacket(f *fairFlow[T], size int, value T, at time.Duration, weight int) {
	if f.head > 0 && len(f.packets) == cap(f.packets) {
		n := copy(f.packets, f.packets[f.head:])
		clear(f.packets[n:])
		f.packets = f.packets[:n]
		f.head = 0
	}
	f.packets = append(f.packets, queued[T]{value: value, bytes: size, weight: min(4, max(1, weight)), at: at})
	q.count++
	f.bytes += int64(size)
	q.bytes += int64(size)
	if q.notify != nil {
		select {
		case q.notify <- struct{}{}:
		default:
		}
	}
}

// remove returns the dequeued item and whether its flow remains active.
// The caller holds mu. Returned values are not released while mu is held.
func (q *FairQueue[T]) remove(f *fairFlow[T]) (queued[T], bool) {
	p := f.packets[f.head]
	var zero queued[T]
	f.packets[f.head] = zero
	f.head++
	f.bytes -= int64(p.bytes)
	q.count--
	q.bytes -= int64(p.bytes)
	if f.head == len(f.packets) {
		q.unlinkFlow(f)
		delete(q.flows, f.key)
		if q.recent == f {
			q.recent = nil
		}
		// A detached flow has no outstanding item references; recycle its
		// descriptor and the small queue backing slice on the next admission.
		arr := f.packets[:0]
		if cap(arr) > min(128, q.cfg.MaxPackets) {
			arr = nil
		}
		*f = fairFlow[T]{packets: arr}
		q.pool.Put(f)
		return p, false
	}
	if f.head > 64 && f.head >= len(f.packets)/2 {
		active := len(f.packets) - f.head
		copy(f.packets, f.packets[f.head:])
		clear(f.packets[active:])
		f.packets, f.head = f.packets[:active], 0
	}
	return p, true
}

// Pop schedules a packet by byte-aware DRR and applies CoDel-style AQM.
// The caller MUST release any returned dropped values. Pool release callbacks
// must happen outside this queue's mutex.
func (q *FairQueue[T]) Pop(now time.Time) (value T, ok bool, dropped []T) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.pop(queueTime(now))
}
func (q *FairQueue[T]) pop(now time.Duration) (value T, ok bool, dropped []T) {
	for q.head != nil {
		f := q.head
		p := f.packets[f.head]
		if f.deficit < p.bytes {
			if q.head == q.tail {
				// With a single active flow DRR has nobody to rotate to.
				// Avoid O(packetSize/quantum) busy looping for GSO/jumbo
				// frames without changing byte fairness under contention.
				f.deficit = p.bytes
			} else {
				// Bounded weights preserve a minimum service share for bulk flows.
				f.deficit += q.cfg.Quantum * p.weight
				q.moveToBack(f)
				continue
			}
		}
		delay := queueDelay(now, p.at)
		if delay > q.maxSojourn {
			q.maxSojourn = delay
		}
		congested := delay > q.cfg.Target && q.bytes > int64(q.cfg.Quantum) && q.count > 1
		if !congested {
			f.firstAboveSet = false
			f.dropping = false
			f.dropCount = 0
		} else if !f.firstAboveSet {
			f.firstAbove = now + q.cfg.Interval
			f.firstAboveSet = true
		}
		shouldDrop := congested && (f.dropping && now >= f.dropNext ||
			!f.dropping && f.firstAboveSet && now >= f.firstAbove)
		if shouldDrop {
			if !f.dropping {
				f.dropping = true
				f.dropCount = 0
			}
			f.dropCount++
			f.dropNext = now + time.Duration(float64(q.cfg.Interval)/math.Sqrt(float64(f.dropCount)))
			old, _ := q.remove(f)
			q.dropped++
			dropped = append(dropped, old.value)
			continue
		}
		chosen, alive := q.remove(f)
		q.dequeued++
		if alive {
			f.deficit -= chosen.bytes
			if f.deficit < f.packets[f.head].bytes {
				q.moveToBack(f)
			}
		}
		return chosen.value, true, dropped
	}
	return value, false, dropped
}

// Drain transfers all pending values to their owner on shutdown.
func (q *FairQueue[T]) Drain() []T {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.drain()
}
func (q *FairQueue[T]) drain() []T {
	all := make([]T, 0, q.count)
	for q.head != nil {
		p, _ := q.remove(q.head)
		all = append(all, p.value)
	}
	return all
}

func (q *FairQueue[T]) Stats() FairStats {
	q.mu.Lock()
	defer q.mu.Unlock()
	return FairStats{
		Packets: q.count, Bytes: q.bytes, Flows: len(q.flows),
		Rejected: q.rejected, DroppedAQM: q.dropped, Dequeued: q.dequeued,
		MaxSojourn: int64(q.maxSojourn),
	}
}

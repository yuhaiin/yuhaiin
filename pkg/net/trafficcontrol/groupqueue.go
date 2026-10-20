package trafficcontrol

import (
	"sync"
	"time"
)

// GroupedFairQueue performs two-tier fair scheduling: byte-aware DRR across
// trusted egress hosts/peers and FQ-CoDel within each host. Opening more flows
// does not grant a host more outer scheduling turns. This is a bounded
// alternative to flat five-tuple fairness, not full CAKE host isolation.
type GroupedFairQueue[T any] struct {
	mu                          sync.Mutex
	cfg                         FairConfig
	groups                      map[uint64]*queueGroup[T]
	head, tail                  *queueGroup[T]
	packets, bytes              int64
	rejected, dropped, dequeued uint64
	maxSojourn                  time.Duration
	notify                      chan struct{}
}
type queueGroup[T any] struct {
	key        uint64
	inner      *FairQueue[groupPacket[T]]
	prev, next *queueGroup[T]
	deficit    int
}
type groupPacket[T any] struct {
	value T
	bytes int
}

func NewGroupedFairQueue[T any](cfg FairConfig) *GroupedFairQueue[T] {
	// NewFairQueue performs the common bounds and defaults validation.
	inner := NewFairQueue[groupPacket[T]](cfg)
	return &GroupedFairQueue[T]{
		cfg: inner.cfg, groups: make(map[uint64]*queueGroup[T]),
		notify: make(chan struct{}, 1),
	}
}
func (q *GroupedFairQueue[T]) Notify() <-chan struct{} { return q.notify }
func (q *GroupedFairQueue[T]) HasCapacity() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.packets < int64(q.cfg.MaxPackets) && q.bytes < q.cfg.MaxBytes
}
func (q *GroupedFairQueue[T]) add(g *queueGroup[T]) {
	g.prev = q.tail
	if q.tail != nil {
		q.tail.next = g
	} else {
		q.head = g
	}
	q.tail = g
}
func (q *GroupedFairQueue[T]) remove(g *queueGroup[T]) {
	if g.prev != nil {
		g.prev.next = g.next
	} else {
		q.head = g.next
	}
	if g.next != nil {
		g.next.prev = g.prev
	} else {
		q.tail = g.prev
	}
	delete(q.groups, g.key)
	g.prev, g.next = nil, nil
}
func (q *GroupedFairQueue[T]) rotate(g *queueGroup[T]) {
	if q.tail == g {
		return
	}
	if g.prev != nil {
		g.prev.next = g.next
	} else {
		q.head = g.next
	}
	g.next.prev = g.prev
	g.prev = q.tail
	g.next = nil
	q.tail.next = g
	q.tail = g
}
func (q *GroupedFairQueue[T]) Push(group, flow uint64, size int, v T, at time.Time, weight int) bool {
	if size <= 0 {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.packets >= int64(q.cfg.MaxPackets) || int64(size) > q.cfg.MaxBytes-q.bytes {
		q.rejected++
		return false
	}
	g := q.groups[group]
	if g == nil {
		g = &queueGroup[T]{key: group, inner: NewFairQueue[groupPacket[T]](q.cfg), deficit: q.cfg.Quantum}
		q.groups[group] = g
		q.add(g)
	}
	if !g.inner.PushWeighted(flow, size, groupPacket[T]{value: v, bytes: size}, at, weight) {
		q.rejected++
		if g.inner.Stats().Packets == 0 {
			q.remove(g)
		}
		return false
	}
	q.packets++
	q.bytes += int64(size)
	select {
	case q.notify <- struct{}{}:
	default:
	}
	return true
}
func (q *GroupedFairQueue[T]) Pop(now time.Time) (out T, ok bool, dropped []T) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for q.head != nil {
		g := q.head
		if g.deficit <= 0 {
			if q.head == q.tail {
				// A lone host cannot borrow bandwidth from another group.
				// Skip pointless quantum rotations for GSO/jumbo packets.
				g.deficit = q.cfg.Quantum
			} else {
				g.deficit += q.cfg.Quantum
				q.rotate(g)
				continue
			}
		}
		packet, found, disc := g.inner.Pop(now)
		for _, d := range disc {
			q.packets--
			q.bytes -= int64(d.bytes)
			q.dropped++
			dropped = append(dropped, d.value)
		}
		if found {
			q.packets--
			q.bytes -= int64(packet.bytes)
			q.dequeued++
			g.deficit -= packet.bytes
		}
		stats := g.inner.Stats()
		if stats.MaxSojourn > q.maxSojourn {
			q.maxSojourn = stats.MaxSojourn
		}
		if stats.Packets == 0 {
			q.remove(g)
		} else if g.deficit <= 0 {
			g.deficit += q.cfg.Quantum
			q.rotate(g)
		}
		if found {
			return packet.value, true, dropped
		}
	}
	return out, false, dropped
}
func (q *GroupedFairQueue[T]) Drain() []T {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]T, 0, q.packets)
	for q.head != nil {
		g := q.head
		for _, p := range g.inner.Drain() {
			out = append(out, p.value)
		}
		q.remove(g)
	}
	q.packets, q.bytes = 0, 0
	return out
}
func (q *GroupedFairQueue[T]) Stats() FairStats {
	q.mu.Lock()
	defer q.mu.Unlock()
	return FairStats{
		Packets: q.packets, Bytes: q.bytes, Flows: len(q.groups),
		Rejected: q.rejected, DroppedAQM: q.dropped, Dequeued: q.dequeued,
		MaxSojourn: q.maxSojourn,
	}
}

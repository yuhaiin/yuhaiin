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
	recent                      *queueGroup[T]
	packets, bytes              int64
	rejected, dropped, dequeued uint64
	maxSojourn                  time.Duration
	overloadDropped             uint64
	notify                      chan struct{}
	flowPool                    *sync.Pool
	spare                       []*queueGroup[T]
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
		cfg: inner.cfg, groups: make(map[uint64]*queueGroup[T]), flowPool: &sync.Pool{New: func() any { return new(fairFlow[groupPacket[T]]) }},
		notify: make(chan struct{}, 1),
	}
}
func (q *GroupedFairQueue[T]) Notify() <-chan struct{} { return q.notify }
func (q *GroupedFairQueue[T]) HasCapacity() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.hasCapacity(0)
}

// Core methods below require exclusive ownership, supplied by mu for public
// operations or by fairOutput.mu for the production output adapter.
func (q *GroupedFairQueue[T]) hasCapacity(bytes int) bool {
	if q.packets == 0 {
		return int64(bytes) <= q.cfg.MaxBytes
	}
	return q.packets < int64(max(1, q.cfg.MaxPackets-1)) && int64(bytes) <= q.flowByteLimit()-q.bytes
}
func (q *GroupedFairQueue[T]) flowByteLimit() int64 {
	return max(int64(1), q.cfg.MaxBytes-min(int64(q.cfg.Quantum), q.cfg.MaxBytes/4))
}
func (q *GroupedFairQueue[T]) group(key uint64) *queueGroup[T] {
	if g := q.recent; g != nil && g.key == key {
		return g
	}
	q.recent = q.groups[key]
	return q.recent
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
	if q.recent == g {
		q.recent = nil
	}
	g.prev, g.next = nil, nil
	// Avoid retaining one maximum-size map for every previously busy group.
	if g.inner.maxFlows > 16 {
		g.inner.flows = make(map[uint64]*fairFlow[groupPacket[T]])
	}
	g.inner.maxFlows = 0
	if len(q.spare) < min(q.cfg.MaxPackets, 64) {
		q.spare = append(q.spare, g)
	}
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
	return q.push(group, flow, size, v, queueTime(at), weight)
}
func (q *GroupedFairQueue[T]) push(group, flow uint64, size int, v T, at time.Duration, weight int) bool {
	if q.packets >= int64(q.cfg.MaxPackets) || int64(size) > q.cfg.MaxBytes-q.bytes {
		q.rejected++
		return false
	}
	g := q.group(group)
	if g == nil {
		if n := len(q.spare); n > 0 {
			g = q.spare[n-1]
			q.spare[n-1] = nil
			q.spare = q.spare[:n-1]
			g.key, g.deficit = group, q.cfg.Quantum
		} else {
			g = &queueGroup[T]{key: group, inner: &FairQueue[groupPacket[T]]{cfg: q.cfg, flows: make(map[uint64]*fairFlow[groupPacket[T]]), pool: q.flowPool}, deficit: q.cfg.Quantum}
		}
		q.groups[group] = g
		q.recent = g
		q.add(g)
	}
	if !g.inner.pushWeighted(flow, size, groupPacket[T]{value: v, bytes: size}, at, weight) {
		q.rejected++
		if g.inner.count == 0 {
			q.remove(g)
		}
		return false
	}
	q.packets++
	q.bytes += int64(size)
	if q.notify != nil {
		select {
		case q.notify <- struct{}{}:
		default:
		}
	}
	return true
}

// Admit may shed packets from the heaviest backlog to admit a new/light
// identity. Returned values transfer their ownership to the caller, which must
// release them outside queue locks. Normal admissions never scan active flows.
func (q *GroupedFairQueue[T]) Admit(group, flow uint64, size int, v T, at time.Time, weight int) (bool, []T) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.admit(group, flow, size, v, queueTime(at), weight)
}
func (q *GroupedFairQueue[T]) admit(group, flow uint64, size int, v T, at time.Duration, weight int) (bool, []T) {
	if size <= 0 || int64(size) > q.cfg.MaxBytes {
		q.rejected++
		return false, nil
	}
	// Keep one descriptor available for another flow where the configured
	// capacity permits it. Established TCP producers receive backpressure rather
	// than losing a packet whose transport has already transferred ownership.
	if g := q.group(group); g != nil {
		if f := g.inner.flow(flow); f != nil && (len(f.packets)-f.head >= max(1, q.cfg.MaxPackets-1) || int64(size) > q.flowByteLimit()-f.bytes) {
			q.rejected++
			return false, nil
		}
	}
	var dropped []T
	for q.packets >= int64(q.cfg.MaxPackets) || int64(size) > q.cfg.MaxBytes-q.bytes {
		incoming := q.group(group)
		var victim *queueGroup[T]
		for g := q.head; g != nil; g = g.next {
			if victim == nil || g.inner.bytes > victim.inner.bytes {
				victim = g
			}
		}
		if victim == nil {
			q.rejected++
			return false, dropped
		}
		var heavy *fairFlow[groupPacket[T]]
		for f := victim.inner.head; f != nil; f = f.next {
			if heavy == nil || f.bytes > heavy.bytes {
				heavy = f
			}
		}
		if victim == incoming || incoming != nil && incoming.inner.bytes >= victim.inner.bytes {
			q.rejected++
			return false, dropped
		}
		packet, _ := victim.inner.remove(heavy)
		q.packets--
		q.bytes -= int64(packet.bytes)
		q.overloadDropped++
		dropped = append(dropped, packet.value.value)
		if victim.inner.count == 0 {
			q.remove(victim)
		}
	}
	return q.push(group, flow, size, v, at, weight), dropped
}

func (q *GroupedFairQueue[T]) Pop(now time.Time) (out T, ok bool, dropped []T) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.pop(queueTime(now))
}
func (q *GroupedFairQueue[T]) pop(now time.Duration) (out T, ok bool, dropped []T) {
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
		packet, found, disc := g.inner.pop(now)
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
		if g.inner.maxSojourn > q.maxSojourn {
			q.maxSojourn = g.inner.maxSojourn
		}
		if g.inner.count == 0 {
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
	return q.drain()
}
func (q *GroupedFairQueue[T]) drain() []T {
	out := make([]T, 0, q.packets)
	for q.head != nil {
		g := q.head
		for _, p := range g.inner.drain() {
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
	return q.stats()
}
func (q *GroupedFairQueue[T]) stats() FairStats {
	return FairStats{
		Packets: q.packets, Bytes: q.bytes, Flows: len(q.groups),
		Rejected: q.rejected, DroppedAQM: q.dropped, DroppedOverload: q.overloadDropped, Dequeued: q.dequeued,
		MaxSojourn: q.maxSojourn,
	}
}

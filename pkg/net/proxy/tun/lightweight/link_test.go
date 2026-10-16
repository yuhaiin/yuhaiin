package lightweight

import (
	"bytes"
	"container/heap"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type linkProfile struct {
	name               string
	rtt, jitter        time.Duration
	lossPPM            int
	bytesPerSecond     int64
	queue, mtu         int
	duplicate, reorder int
}

var linkProfiles = []linkProfile{
	{name: "rtt1ms", rtt: time.Millisecond, queue: 256, mtu: 1500},
	{name: "rtt10ms", rtt: 10 * time.Millisecond, queue: 256, mtu: 1500},
	{name: "rtt50ms-loss0.1pct", rtt: 50 * time.Millisecond, jitter: time.Millisecond, lossPPM: 1000, queue: 256, mtu: 1500},
	{name: "rtt100ms-loss1pct", rtt: 100 * time.Millisecond, jitter: 2 * time.Millisecond, lossPPM: 10000, queue: 256, mtu: 1500},
	{name: "rtt100ms-10Mbps-queue32", rtt: 100 * time.Millisecond, bytesPerSecond: 1250000, queue: 32, mtu: 1500},
}

type queuedPacket struct {
	at  time.Time
	b   []byte
	out bool
}
type wireHeap []queuedPacket

func (h wireHeap) Len() int           { return len(h) }
func (h wireHeap) Less(i, j int) bool { return h[i].at.Before(h[j].at) }
func (h wireHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *wireHeap) Push(v any)        { *h = append(*h, v.(queuedPacket)) }
func (h *wireHeap) Pop() any {
	a := *h
	v := a[len(a)-1]
	a[len(a)-1] = queuedPacket{}
	*h = a[:len(a)-1]
	return v
}

type simulatedIO struct {
	base       PacketIO
	profile    linkProfile
	mu         sync.Mutex
	wire       wireHeap
	next       [2]time.Time
	rng        uint64
	counts     [2]int
	incoming   chan []byte
	wake, done chan struct{}
	once       sync.Once
	wg         sync.WaitGroup
	drops      atomic.Uint64
}

func simulate(base PacketIO, p linkProfile) *simulatedIO {
	q := &simulatedIO{base: base, profile: p, rng: 0x5eed1234, incoming: make(chan []byte, p.queue), wake: make(chan struct{}, 1), done: make(chan struct{})}
	q.wg.Go(q.readLoop)
	q.wg.Go(q.dispatch)
	return q
}
func (q *simulatedIO) random() uint64 {
	q.rng ^= q.rng << 13
	q.rng ^= q.rng >> 7
	q.rng ^= q.rng << 17
	return q.rng
}
func (q *simulatedIO) enqueue(b []byte, out bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	select {
	case <-q.done:
		return
	default:
	}
	if len(b) > q.profile.mtu || len(q.wire) >= q.profile.queue || int(q.random()%1000000) < q.profile.lossPPM {
		q.drops.Add(1)
		return
	}
	dir := 0
	if out {
		dir = 1
	}
	q.counts[dir]++
	now := time.Now()
	at := now
	if q.profile.bytesPerSecond > 0 {
		at = maxTime(now, q.next[dir]).Add(time.Duration(float64(len(b)) / float64(q.profile.bytesPerSecond) * float64(time.Second)))
		q.next[dir] = at
	}
	at = at.Add(q.profile.rtt / 2)
	if q.profile.jitter > 0 {
		at = at.Add(time.Duration(int64(q.random()%uint64(2*q.profile.jitter+1)) - int64(q.profile.jitter)))
	}
	if q.profile.reorder > 0 && q.counts[dir]%q.profile.reorder == 0 {
		at = at.Add(q.profile.rtt)
	}
	heap.Push(&q.wire, queuedPacket{at, bytes.Clone(b), out})
	if q.profile.duplicate > 0 && q.counts[dir]%q.profile.duplicate == 0 && len(q.wire) < q.profile.queue {
		heap.Push(&q.wire, queuedPacket{at.Add(time.Microsecond), bytes.Clone(b), out})
	}
	select {
	case q.wake <- struct{}{}:
	default:
	}
}
func (q *simulatedIO) stop() { q.once.Do(func() { close(q.done); _ = q.base.Close() }) }
func (q *simulatedIO) readLoop() {
	defer q.stop()
	b := make([]byte, 65575)
	for {
		n, err := q.base.ReadPacket(b)
		if err != nil {
			return
		}
		q.enqueue(b[:n], false)
	}
}
func (q *simulatedIO) dispatch() {
	defer q.stop()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		q.mu.Lock()
		var wait <-chan time.Time
		if len(q.wire) > 0 {
			d := time.Until(q.wire[0].at)
			if d <= 0 {
				p := heap.Pop(&q.wire).(queuedPacket)
				q.mu.Unlock()
				if p.out {
					if err := q.base.WritePacket(p.b); err != nil {
						return
					}
				} else {
					select {
					case q.incoming <- p.b:
					default:
						q.drops.Add(1)
					}
				}
				continue
			}
			timer.Reset(d)
			wait = timer.C
		} else {
			timer.Stop()
		}
		q.mu.Unlock()
		select {
		case <-q.done:
			return
		case <-q.wake:
		case <-wait:
		}
	}
}
func (q *simulatedIO) ReadPacket(b []byte) (int, error) {
	select {
	case <-q.done:
		return 0, net.ErrClosed
	case p := <-q.incoming:
		if len(p) > len(b) {
			return 0, io.ErrShortBuffer
		}
		return copy(b, p), nil
	}
}
func (q *simulatedIO) WritePacket(b []byte) error {
	select {
	case <-q.done:
		return net.ErrClosed
	default:
		q.enqueue(b, true)
		return nil
	}
}
func (q *simulatedIO) Close() error {
	q.stop()
	q.wg.Wait()
	q.mu.Lock()
	q.wire = nil
	q.mu.Unlock()
	return nil
}

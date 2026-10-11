package ike

// Constant-rate transmission for RFC 9347 IP-TFS.
//
// This is the half of IP-TFS the name is about, and the half every other
// implementation leaves out. strongSwan and the Linux kernel do AGGFRAG's
// aggregation and fragmentation; neither transmits at a constant rate. veepin
// does ESP in userspace and is not bound by the kernel's data path, so it can.
//
// What it changes, and why a knob on the shaper could not:
//
//	plain ESP        one datagram per inner packet, when the packet arrives.
//	                 Sizes shaped, counts and timing not. An observer counting
//	                 packets and their gaps sees the traffic inside.
//	constant-rate    one datagram every interval, ALWAYS, of the same size.
//	IP-TFS           Idle or saturated, the stream on the wire is identical;
//	                 what varies is only how much of each payload is padding.
//
// dataplane.Shaper cannot do this and no amount of tuning would let it: it pads
// packets the pump is already sending, so its output is still one datagram per
// input packet at the moment the input arrived. The signal removed here is the
// schedule, not the sizes, which is why this needed a new seam
// (dataplane.PacedTunnel) rather than a new option.
//
// # The cost, stated plainly
//
// It sends continuously. At 10 Mbit/s an idle tunnel still moves 10 Mbit/s of
// padding, forever, in both directions if both ends enable it. That is the
// price of the property and it is why the option is off by default and why
// -iptfs-rate takes a number rather than a boolean: the operator has to choose
// what they are willing to spend.
//
// # The honest limit
//
// The interval is payloadSize/rate. At 1400-octet payloads that is 1.12 ms at
// 10 Mbit/s, 112 µs at 100 Mbit/s, and 11 µs at 1 Gbit/s -- below what a Go
// timer will deliver reliably. Above roughly 100 Mbit/s the sender therefore
// falls behind its own ticker and emits the backlog as a burst on the next
// tick, which is a weaker property than a constant rate: an observer sees the
// burst boundaries rather than a smooth stream. It is still independent of the
// offered load, which is the security claim, but the timing is quantised by the
// runtime rather than by the configuration. burstsFor reports what a given rate
// will actually produce, and TestTheRateAboveWhichTimingIsQuantised pins where
// the boundary is so the docs cannot drift from it.

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev2/aggfrag"
)

// pacerQueueDepth is how many inner packets may wait for their turn.
//
// Deep enough to ride out a burst between ticks, shallow enough that a packet
// which does get through is recent. A constant-rate tunnel cannot speed up to
// drain a backlog -- that is the property -- so a deep queue does not raise
// throughput, it only converts drops into latency, and latency on a queue that
// can never catch up is worse than a drop the sender is told about.
const pacerQueueDepth = 256

// iptfsPayloadSize is the AGGFRAG payload every paced datagram carries, header
// included. It is a constant and not a tunable, because the size being fixed IS
// the property: a payload sized to the traffic would put the traffic's size
// distribution back on the wire, which is the thing that was removed.
//
// 1400 is client.DefaultTunnelMTU, spelled here rather than imported so this
// package keeps its own dependency graph. It leaves room for the ESP and outer
// IP/UDP headers inside a 1500-octet path, which is the same reasoning that
// picked the tunnel MTU.
const iptfsPayloadSize = 1400

// pacerMinInterval is the floor on the ticker period. Below it the runtime
// cannot deliver ticks reliably and the sender would spend its time being late,
// so it instead sends several payloads per tick and says so through burstsFor.
const pacerMinInterval = 100 * time.Microsecond

// pacedTunnel is an aggfragTunnel that transmits on a fixed schedule.
//
// Its Encapsulate is never called by the pump -- routeOutbound hands packets to
// Enqueue instead -- but it is still inherited and still correct, which matters
// because the tunnel is also what a rekey copies from.
type pacedTunnel struct {
	*aggfragTunnel

	// payloadSize is the AGGFRAG payload length, header included. Every
	// datagram carries exactly this many octets of plaintext, which is what
	// makes the size independent of the traffic.
	payloadSize int
	// interval is the gap between transmissions, and perTick how many payloads
	// each tick emits. Their product over time is the configured rate; perTick
	// is 1 until the interval hits pacerMinInterval.
	interval time.Duration
	perTick  int

	queue chan []byte
	free  chan []byte

	startOnce sync.Once
	stopOnce  sync.Once
	stop      chan struct{}
	done      chan struct{}

	// sent counts datagrams actually transmitted, which is deliberately NOT
	// the pump's TxPackets: that counts what the caller offered. The two
	// diverging is the normal state of a constant-rate tunnel and the pair is
	// what an operator reads to see how much of the rate is padding.
	sent atomic.Uint64
}

// newPacedTunnel wraps t so it transmits rateBytesPerSec octets per second in
// payloads of payloadSize octets, regardless of what the TUN offers.
func newPacedTunnel(t *aggfragTunnel, rateBytesPerSec, payloadSize int) *pacedTunnel {
	interval, perTick := pacing(rateBytesPerSec, payloadSize)
	return &pacedTunnel{
		aggfragTunnel: t,
		payloadSize:   payloadSize,
		interval:      interval,
		perTick:       perTick,
		queue:         make(chan []byte, pacerQueueDepth),
		free:          make(chan []byte, pacerQueueDepth),
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
}

// pacing resolves a rate into a ticker period and a per-tick payload count.
//
// The two are separate because a timer has a floor a configuration does not. At
// or above pacerMinInterval one payload per tick gives the exact rate; below it
// the period is clamped and the count grows to compensate, which keeps the rate
// and quantises the timing. Saying which happened is what burstsFor is for.
func pacing(rateBytesPerSec, payloadSize int) (time.Duration, int) {
	if rateBytesPerSec <= 0 || payloadSize <= 0 {
		return 0, 0
	}
	// Nanoseconds per payload, computed in integer arithmetic so a slow rate
	// does not lose precision to a float.
	perPayload := time.Duration(int64(payloadSize) * int64(time.Second) / int64(rateBytesPerSec))
	if perPayload >= pacerMinInterval {
		return perPayload, 1
	}
	if perPayload <= 0 {
		perPayload = 1
	}
	n := int((pacerMinInterval + perPayload - 1) / perPayload)
	return pacerMinInterval, max(n, 1)
}

// burstsFor reports whether a rate is above the point at which the sender emits
// bursts rather than a smooth stream, and how many payloads a burst holds.
//
// It is exported to the package (and pinned by a test) so the number in the
// documentation and the number in the code cannot drift: "roughly 100 Mbit/s"
// is a claim, and this is where it is checked.
func burstsFor(rateBytesPerSec, payloadSize int) (bursty bool, perTick int) {
	_, n := pacing(rateBytesPerSec, payloadSize)
	return n > 1, n
}

// Enqueue takes a copy of one inner packet for transmission.
//
// A full queue drops rather than blocks. Blocking would stall the pump's single
// TUN reader, which would push back on every other tunnel it serves -- so one
// tunnel configured below its offered load would degrade the whole data path.
func (p *pacedTunnel) Enqueue(pkt []byte) bool {
	var buf []byte
	select {
	case buf = <-p.free:
		buf = buf[:0]
	default:
		buf = make([]byte, 0, p.payloadSize)
	}
	buf = append(buf, pkt...)
	select {
	case p.queue <- buf:
		return true
	default:
		// Hand the buffer back rather than letting it go: the free list is what
		// keeps a steady send loop from allocating, and a burst that drops
		// would otherwise empty it.
		select {
		case p.free <- buf:
		default:
		}
		return false
	}
}

// StartPacing begins transmission. It is idempotent, because AddTunnel may run
// twice for one tunnel across a rekey.
func (p *pacedTunnel) StartPacing(send dataplane.Sender) {
	p.startOnce.Do(func() { go p.run(send) })
}

// StopPacing ends transmission and waits for the sender to finish, so a caller
// that tears a tunnel down knows nothing more will be written for it.
func (p *pacedTunnel) StopPacing() {
	p.stopOnce.Do(func() { close(p.stop) })
	<-p.done
}

// run is the sender: every tick, fill one payload (or perTick of them) and
// transmit, whether or not there is anything to carry.
//
// The unconditional send is the entire point and the easiest thing to
// "optimise" away. A sender that skipped idle ticks would produce a datagram
// stream that starts when traffic starts and stops when it stops, which is the
// signal this exists to remove -- and it would still pass a ping test, a
// throughput test, and an interop cell.
func (p *pacedTunnel) run(send dataplane.Sender) {
	defer close(p.done)
	if p.interval <= 0 {
		return
	}
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	var ready [][]byte
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			for range p.perTick {
				ready = p.fill(ready)
				payload, remaining := p.packer.Pack(ready, p.payloadSize)
				p.recycle(ready[:len(ready)-len(remaining)])
				ready = append(ready[:0], remaining...)

				out, err := p.espSA.Encapsulate(payload, aggfrag.ESPNextHeader)
				if err != nil {
					continue
				}
				p.sent.Add(1)
				send(out, p.PeerAddr())
			}
		}
	}
}

// fill tops up the ready list from the queue without blocking. It takes only
// what is already waiting: a tick must not wait for traffic that has not
// arrived, or the schedule would follow the load again.
func (p *pacedTunnel) fill(ready [][]byte) [][]byte {
	for len(ready) < pacerQueueDepth {
		select {
		case pkt := <-p.queue:
			ready = append(ready, pkt)
		default:
			return ready
		}
	}
	return ready
}

// recycle returns consumed buffers to the free list.
func (p *pacedTunnel) recycle(used [][]byte) {
	for _, b := range used {
		select {
		case p.free <- b[:0]:
		default:
			return // the list is full; let the rest be collected
		}
	}
}

// Sent reports how many datagrams the pacer has transmitted. Together with the
// pump's TxPackets for this tunnel -- which counts what was OFFERED -- it is how
// an operator sees what fraction of the rate is padding.
func (p *pacedTunnel) Sent() uint64 { return p.sent.Load() }

// PeerAddr is inherited, but stated here because the sender calls it on every
// datagram and a reader should not have to find out that it is not cached: a
// MOBIKE roam changes it, and a pacer holding a stale copy would keep
// transmitting to an address the peer has left.
func (p *pacedTunnel) PeerAddr() *net.UDPAddr { return p.aggfragTunnel.PeerAddr() }

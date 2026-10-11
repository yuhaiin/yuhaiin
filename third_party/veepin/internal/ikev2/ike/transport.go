package ike

import (
	"net"
	"sync"

	"github.com/xen0bit/veepin/dataplane"
)

// nonESPMarker is the 4-octet zero prefix that distinguishes an IKE message
// from an ESP packet on the NAT-T port 4500 (RFC 3948 section 2.2). ESP packets
// begin with a non-zero SPI, so a zero prefix means "this is IKE".
var nonESPMarker = []byte{0, 0, 0, 0}

// espSocketHandler is called for ESP datagrams received on port 4500 (after the
// non-ESP marker check). The bytes are the raw ESP packet (SPI first).
type espSocketHandler func(esp []byte, from *net.UDPAddr)

// espSocketBatchHandler is the batch form: every ESP datagram of one read
// batch at once, so the data path can coalesce inbound TCP (GRO) with the
// batch as its window. Preferred over espSocketHandler when set.
type espSocketBatchHandler func(esp [][]byte, froms []*net.UDPAddr)

// transport owns the two UDP sockets an IKEv2/NAT-T responder needs: port 500
// for the initial exchange and port 4500 for post-NAT-detection traffic and
// UDP-encapsulated ESP.
type transport struct {
	conn500    *dataplane.PacketConn
	conn4500   *dataplane.PacketConn
	onESP      espSocketHandler
	onESPBatch espSocketBatchHandler

	// tcpLn is the RFC 8229/9329 listener on TCP 4500, or nil when TCP
	// encapsulation is off. It sits BESIDE the UDP sockets rather than instead
	// of them, which is what makes libreswan's `enable-tcp=fallback` work
	// without a mode switch: a peer is answered on whatever it arrived on, and
	// the server never has to decide in advance.
	tcpLn net.Listener
	// streams maps a peer's address -- the same string key the SA table uses --
	// to its stream. It is the whole of what the send path needs to know about
	// which transport an SA arrived on: sendIKE and sendESP look here first and
	// fall through to UDP, so nothing above this file branches.
	smu     sync.RWMutex
	streams map[string]*TCPStream
}

// stream returns the TCP stream serving a peer, or nil if that peer is on UDP.
func (t *transport) stream(to *net.UDPAddr) *TCPStream {
	if to == nil {
		return nil
	}
	t.smu.RLock()
	defer t.smu.RUnlock()
	return t.streams[to.String()]
}

func (t *transport) addStream(key string, st *TCPStream) {
	t.smu.Lock()
	defer t.smu.Unlock()
	if t.streams == nil {
		t.streams = make(map[string]*TCPStream)
	}
	t.streams[key] = st
}

func (t *transport) removeStream(key string) {
	t.smu.Lock()
	defer t.smu.Unlock()
	delete(t.streams, key)
}

// sendIKE transmits an IKE message to a peer. When the peer is on port 4500 the
// non-ESP marker is prepended.
func (t *transport) sendIKE(pkt []byte, to *net.UDPAddr, on4500 bool) error {
	if st := t.stream(to); st != nil {
		return st.WriteIKE(pkt)
	}
	if on4500 {
		framed := make([]byte, 0, len(nonESPMarker)+len(pkt))
		framed = append(framed, nonESPMarker...)
		framed = append(framed, pkt...)
		_, err := t.conn4500.WriteToUDP(framed, to)
		return err
	}
	_, err := t.conn500.WriteToUDP(pkt, to)
	return err
}

// sendESP transmits an encapsulated ESP datagram. With NAT-T (udpEncap) the ESP
// bytes go out on port 4500 as-is (a non-zero SPI is its own marker). Without
// NAT-T there is no raw-IP ESP path in this userspace build, so ESP is always
// UDP-encapsulated on 4500 when a tunnel is up.
func (t *transport) sendESP(esp []byte, to *net.UDPAddr) error {
	if st := t.stream(to); st != nil {
		return st.WriteESP(esp)
	}
	_, err := t.conn4500.WriteToUDP(esp, to)
	return err
}

// sendESPBatch flushes a burst of ESP packets for one peer: one sendmmsg on
// UDP, one write carrying several frames on a stream.
func (t *transport) sendESPBatch(esp [][]byte, to *net.UDPAddr) error {
	if st := t.stream(to); st != nil {
		return st.WriteESPBatch(esp)
	}
	_, err := t.conn4500.WriteBatch(esp, to)
	return err
}

// serve runs the read loops for both sockets -- and the TCP accept loop when
// one is configured -- dispatching IKE messages to handleIKE and ESP datagrams
// to the ESP handler. It returns when every loop has finished.
func (t *transport) serve(handleIKE func(pkt []byte, from *net.UDPAddr, on4500 bool), closing func() bool) {
	loops := 2
	if t.tcpLn != nil {
		loops++
	}
	done := make(chan struct{}, loops)

	// Port 500: only IKE, no marker.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := t.conn500.ReadFromUDP(buf)
			if err != nil {
				if closing() {
					done <- struct{}{}
					return
				}
				continue
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			handleIKE(pkt, from, false)
		}
	}()

	// Port 4500: non-ESP marker => IKE; otherwise ESP. This is the data-path hot
	// socket — every client's ESP arrives here — so it reads in recvmmsg batches
	// (dataplane.PacketConn.ReadBatch): one syscall drains up to espBatch
	// datagrams when traffic is queued, and blocks for one like a plain read when
	// it is not, so batching adds no latency to an idle tunnel.
	go func() {
		const espBatch = 16
		bufs := make([][]byte, espBatch)
		for i := range bufs {
			bufs[i] = make([]byte, 65535)
		}
		sizes := make([]int, espBatch)
		froms := make([]*net.UDPAddr, espBatch)
		esps := make([][]byte, 0, espBatch)
		espFroms := make([]*net.UDPAddr, 0, espBatch)
		for {
			n, err := t.conn4500.ReadBatch(bufs, sizes, froms)
			esps, espFroms = esps[:0], espFroms[:0]
			for i := range n {
				pkt, from := bufs[i][:sizes[i]], froms[i]
				if len(pkt) >= 4 && pkt[0] == 0 && pkt[1] == 0 && pkt[2] == 0 && pkt[3] == 0 {
					// Non-ESP marker: the rest is an IKE message. Copied out,
					// because IKE handling may outlive this batch's buffers.
					ike := make([]byte, len(pkt)-4)
					copy(ike, pkt[4:])
					handleIKE(ike, from, true)
					continue
				}
				// ESP datagram (non-zero SPI). Collected without a copy: the
				// whole batch is handed over at once so the data path can
				// coalesce (GRO), and the handler chain decapsulates and
				// writes the TUN before returning — bufs[i] is not touched
				// again until the next ReadBatch.
				esps = append(esps, pkt)
				espFroms = append(espFroms, from)
			}
			if len(esps) > 0 {
				switch {
				case t.onESPBatch != nil:
					t.onESPBatch(esps, espFroms)
				case t.onESP != nil:
					for i, esp := range esps {
						t.onESP(esp, espFroms[i])
					}
				}
			}
			if err != nil {
				if closing() {
					done <- struct{}{}
					return
				}
				continue
			}
		}
	}()

	// TCP 4500 (RFC 8229/9329), when enabled. One goroutine per connection
	// beyond the accept loop, because a stream is a per-peer thing where a UDP
	// socket is a per-server one.
	if t.tcpLn != nil {
		go func() {
			for {
				c, err := t.tcpLn.Accept()
				if err != nil {
					if closing() {
						done <- struct{}{}
						return
					}
					continue
				}
				go t.serveStream(c, handleIKE)
			}
		}()
	}

	for range loops {
		<-done
	}
}

// serveStream runs one accepted RFC 8229 connection: consume the originator's
// stream prefix, then dispatch frames until the peer goes away.
//
// The prefix is the responder's first read and the responder sends NONE of its
// own. Getting either half of that wrong is silent in one direction and fatal
// in the other: a responder that waits for a prefix it will not be sent
// deadlocks, and one that sends its own corrupts the first frame the originator
// reads.
func (t *transport) serveStream(c net.Conn, handleIKE func(pkt []byte, from *net.UDPAddr, on4500 bool)) {
	if tc, ok := c.(*net.TCPConn); ok {
		// Nagle would hold a small IKE message waiting for more to send, which
		// on a request/response control exchange means waiting for the answer to
		// the message it is holding.
		_ = tc.SetNoDelay(true)
	}
	st := newTCPStream(c)
	defer c.Close()

	if err := st.r.expectPrefix(); err != nil {
		return
	}

	from := udpAddrOf(c.RemoteAddr())
	key := from.String()
	t.addStream(key, st)
	defer t.removeStream(key)

	// One-element batch, hoisted. The ESP path is the hot loop, and a fresh
	// [][]byte per packet would be exactly the per-packet allocation the
	// datagram side is careful not to make. Nothing retains either slice past
	// the handler call.
	one := make([][]byte, 1)
	oneFrom := []*net.UDPAddr{from}

	for {
		pkt, isIKE, err := st.ReadFrame()
		if err != nil {
			// Either the peer went away or transport.close() closed the stream;
			// neither needs a closing() check, which would take the server's
			// lock once per packet to answer a question a failed read already
			// answers.
			return
		}
		if isIKE {
			// Copied out, because IKE handling may outlive the frame buffer.
			msg := make([]byte, len(pkt))
			copy(msg, pkt)
			// on4500 is true: RFC 8229 carries the non-ESP marker from the very
			// first message, so an IKE message on a stream is always in the
			// state the UDP path only reaches after floating.
			handleIKE(msg, from, true)
			continue
		}
		// The frame borrows the reader's buffer and is valid until the next
		// call; the handler chain decapsulates and writes the TUN before
		// returning, exactly as the UDP batch path relies on.
		switch {
		case t.onESPBatch != nil:
			one[0] = pkt
			t.onESPBatch(one, oneFrom)
		case t.onESP != nil:
			t.onESP(pkt, from)
		}
	}
}

func (t *transport) close() {
	if t.conn500 != nil {
		t.conn500.Close()
	}
	if t.conn4500 != nil {
		t.conn4500.Close()
	}
	if t.tcpLn != nil {
		t.tcpLn.Close()
	}
	// Closing every live stream is what unblocks the per-connection goroutines;
	// closing the listener alone leaves them reading forever.
	t.smu.Lock()
	for k, st := range t.streams {
		st.Close()
		delete(t.streams, k)
	}
	t.smu.Unlock()
}

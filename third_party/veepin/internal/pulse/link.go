package pulse

// The IF-T/TLS data path: bare IP packets in Juniper data messages over the
// same TLS connection authentication ran on.
//
// It is the fallback when ESP is unavailable, and the only path when the server
// offers no ESP at all. Two goroutines own the link: one reads the connection
// and writes what it decodes to the TUN, one reads the TUN and writes framed
// messages back. Both end through stop, which records the first cause.

import (
	"net"
	"net/netip"
	"sync"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/vlog"
)

// maxInnerPacket bounds one inner packet, and with it the read buffer. It is
// comfortably above any tunnel MTU a server will hand out.
const maxInnerPacket = 9000

// link is a running IF-T/TLS data carrier.
type link struct {
	conn   net.Conn
	tun    tunIO
	logger *vlog.Logger
	seq    uint32

	// sourceIs, when set, is the inner address the peer is allowed to send
	// from: a server pins each client to the address it assigned, so a client
	// cannot spoof another's traffic onto the shared TUN.
	sourceIs netip.Addr

	// closeTUN, when set, is called when the link stops. A client's link owns
	// its TUN and closes it; a server's shares one across every client and
	// leaves it alone.
	closeTUN func() error

	mu       sync.Mutex
	writeMu  sync.Mutex
	closed   bool
	err      error
	done     chan struct{}
	shutdown func()
}

func newLink(conn net.Conn, tun tunIO, logger *vlog.Logger) *link {
	return &link{conn: conn, tun: tun, logger: logger, done: make(chan struct{})}
}

// send frames one inner IP packet and writes it. minInner pads the packet out
// towards that size first, which is what the shaper asks for.
//
// The padding is trailing filler after the inner packet, which every IP stack
// discards by reading the header's own Total Length — the same mechanism
// GlobalProtect's tunnel relies on, and the reason a stock client needs no
// support for it.
func (l *link) send(pkt []byte, minInner int) error {
	if minInner > len(pkt) && minInner <= maxInnerPacket {
		padded := make([]byte, minInner)
		copy(padded, pkt)
		pkt = padded
	}
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	msg := EncodeData(l.seq, pkt)
	l.seq++
	_, err := l.conn.Write(msg)
	return err
}

// sendControl writes a control message on the same connection, under the same
// write lock, so it cannot interleave with a data message mid-write.
func (l *link) sendControl(vendor, msgType uint32, payload []byte) error {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	msg := EncodeMessage(vendor, msgType, l.seq, payload)
	l.seq++
	_, err := l.conn.Write(msg)
	return err
}

// readLoop decodes messages off the connection and writes inner packets to the
// TUN. TLS is a stream, so a read can land on any number of whole or partial
// messages; the buffer keeps what is left over.
func (l *link) readLoop() {
	buf := make([]byte, 0, 2*maxInnerPacket)
	tmp := make([]byte, maxInnerPacket)
	for {
		n, err := l.conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			var consumed int
			for {
				m, rest, perr := ParseMessage(buf[consumed:])
				if perr != nil {
					break // an incomplete message: wait for more
				}
				consumed = len(buf) - len(rest)
				l.dispatch(m)
			}
			// Keep only what has not been decoded yet.
			buf = append(buf[:0], buf[consumed:]...)
			if len(buf) > maxInnerPacket+HeaderLen {
				l.stop(errOversizedMessage)
				return
			}
		}
		if err != nil {
			l.stop(err)
			return
		}
	}
}

// dispatch handles one decoded message.
func (l *link) dispatch(m Message) {
	if m.Vendor != VendorJuniper {
		return
	}
	switch m.Type {
	case TypeData:
		// Trim any shaping filler the sender added. The inner IP header's own
		// Total Length delimits the real packet, which is exactly how a kernel
		// would read it — and is what lets a peer that negotiated nothing
		// benefit from shaping unmodified.
		pkt := dataplane.TrimToIP(m.Payload)
		if pkt == nil || !l.allowed(pkt) {
			return
		}
		_, _ = l.tun.Write(pkt)
	case TypeClose:
		l.stop(errPeerClosed)
	}
}

// allowed enforces the anti-spoofing rule: a packet whose source is not the
// address this peer was assigned is dropped rather than written to a TUN
// shared with other peers. A link with no pinned address (a client's) carries
// whatever the server sends.
func (l *link) allowed(pkt []byte) bool {
	if !l.sourceIs.IsValid() {
		return true
	}
	src, ok := sourceOf(pkt)
	return ok && src == l.sourceIs
}

// sourceOf reads an IP packet's source address, for either family.
func sourceOf(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 1 {
		return netip.Addr{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(pkt[12:16])), true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(pkt[8:24])), true
	}
	return netip.Addr{}, false
}

// tunLoop reads the TUN and frames what it finds. shaper, when non-nil, decides
// how far each packet is padded.
func (l *link) tunLoop(target func(pkt []byte) int) {
	buf := make([]byte, maxInnerPacket)
	for {
		n, err := l.tun.Read(buf)
		if err != nil {
			l.stop(err)
			return
		}
		minInner := 0
		if target != nil {
			minInner = target(buf[:n])
		}
		if err := l.send(buf[:n], minInner); err != nil {
			l.stop(err)
			return
		}
	}
}

// stop ends the link once, recording the first cause.
func (l *link) stop(cause error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	l.err = cause
	shutdown := l.shutdown
	l.mu.Unlock()

	close(l.done)
	_ = l.conn.Close()
	if l.closeTUN != nil {
		_ = l.closeTUN()
	}
	if shutdown != nil {
		shutdown()
	}
}

// Wait blocks until the link stops.
func (l *link) Wait() error {
	<-l.done
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

// Close tears the link down.
func (l *link) Close() error {
	// Tell the peer before hanging up, so it releases the session at once
	// rather than at its idle timeout. A failure here is not worth reporting:
	// the connection is going away regardless.
	_ = l.sendControl(VendorJuniper, TypeClose, append([]byte("disconnect"), 0))
	l.stop(nil)
	return nil
}

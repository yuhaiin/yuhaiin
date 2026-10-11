package gp

// The SSL tunnel data path: framed layer-3 packets over the TLS stream.
//
// This is the simpler of the protocol's two data paths and the one that always
// works, because it is the same TLS connection the login already proved it can
// open. There is no PPP and no negotiation — once the gateway has answered
// START_TUNNEL the stream carries nothing but framed packets, so the link is a
// read loop, a write lock and the TUN.
//
// It serves both roles. A client owns its TUN and reads it; a server shares one
// TUN across clients, so its links never read it and never close it, and each
// carries the address its client was assigned so one client cannot inject
// traffic as another.

import (
	"io"
	"net"
	"sync"

	"github.com/xen0bit/veepin/internal/vlog"
)

// maxInnerPacket bounds a packet read from the TUN. It is the framing's own
// ceiling, so a jumbo-framed TUN cannot produce a packet the header cannot
// describe.
const maxInnerPacket = maxFramePayload

// tunnelLink couples a framed connection to a TUN.
type tunnelLink struct {
	conn   net.Conn
	reader io.Reader // read side; nil means read from conn (a hijacked server conn sets it)
	tun    io.ReadWriteCloser
	logger *vlog.Logger

	// ownsTUN is true for a client, which has the TUN to itself; false for a
	// server link, which shares one TUN across clients and must not close it.
	ownsTUN bool
	// assignedSrc, when set, is the only inner source address this link may send.
	// A server sets it; a client leaves it nil.
	assignedSrc net.IP
	// answerKeepalives makes this end reply to the liveness packet. Exactly one
	// end may: if both did, one probe would bounce between them forever.
	answerKeepalives bool

	// alive is signalled on every inbound packet, so a client's liveness probe
	// can wait for evidence the far end is still there. It is buffered and
	// non-blocking, so the read loop never waits on a prober that is not looking.
	alive chan struct{}

	writeMu   sync.Mutex
	done      chan struct{}
	closeOnce sync.Once
	err       error
}

// newLink builds a link with the channels its loops need.
func newLink(conn net.Conn, reader io.Reader, tun io.ReadWriteCloser, logger *vlog.Logger) *tunnelLink {
	if logger == nil {
		logger = vlog.Discard()
	}
	return &tunnelLink{
		conn:   conn,
		reader: reader,
		tun:    tun,
		logger: logger,
		alive:  make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
}

// rd is the read side of the link.
func (l *tunnelLink) rd() io.Reader {
	if l.reader != nil {
		return l.reader
	}
	return l.conn
}

// send writes one inner IP packet to the tunnel. minInner, when non-zero, pads
// the packet out to that many octets before framing it.
//
// The padding is safe against a peer that agreed to nothing: a receiver hands the
// framed body to its TUN, and every IP stack trims an inbound packet to the total
// length in its own header (Linux does it in ip_rcv). That is the same property
// dataplane.TrimToIP relies on, and it is why shaping needs no negotiation.
func (l *tunnelLink) send(pkt []byte, minInner int) error {
	etherType, ok := EtherTypeFor(pkt)
	if !ok {
		// Not an IP packet: nothing on this tunnel can carry it.
		return nil
	}
	if minInner > len(pkt) && minInner <= maxFramePayload {
		padded := make([]byte, minInner)
		copy(padded, pkt)
		pkt = padded
	}
	frame := EncodeFrame(etherType, pkt)

	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	_, err := l.conn.Write(frame)
	return err
}

// sendKeepalive writes the empty liveness packet.
func (l *tunnelLink) sendKeepalive() error {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	_, err := l.conn.Write(EncodeKeepalive())
	return err
}

// readLoop reads framed packets and dispatches them until the connection ends.
func (l *tunnelLink) readLoop() {
	for {
		f, err := ReadFrame(l.rd())
		if err != nil {
			l.stop(err)
			return
		}
		l.signalAlive()
		if f.IsKeepalive() {
			if l.answerKeepalives {
				if err := l.sendKeepalive(); err != nil {
					l.stop(err)
					return
				}
			}
			continue
		}
		if l.assignedSrc != nil && !sourceIs(f.Payload, l.assignedSrc) {
			// A client sending from an address it was not assigned is spoofing;
			// drop it rather than let it reach the shared TUN as another client.
			continue
		}
		if _, err := l.tun.Write(f.Payload); err != nil {
			l.stop(err)
			return
		}
	}
}

// signalAlive records that the far end spoke, without ever blocking the read
// loop on a prober that is not currently waiting.
func (l *tunnelLink) signalAlive() {
	select {
	case l.alive <- struct{}{}:
	default:
	}
}

// tunLoop reads outbound packets and frames each onto the tunnel. Only a client
// runs it; a server's TUN is shared and read in one place.
func (l *tunnelLink) tunLoop() {
	buf := make([]byte, maxInnerPacket)
	for {
		n, err := l.tun.Read(buf)
		if err != nil {
			l.stop(err)
			return
		}
		if err := l.send(buf[:n], 0); err != nil {
			l.stop(err)
			return
		}
	}
}

// stop tears the link down once, recording the first cause. It closes the TUN
// only when it owns it, so a server link ending does not take the shared TUN —
// and every other client — down with it.
func (l *tunnelLink) stop(cause error) {
	l.closeOnce.Do(func() {
		l.err = cause
		close(l.done)
		_ = l.conn.Close()
		if l.ownsTUN && l.tun != nil {
			_ = l.tun.Close()
		}
	})
}

// Wait blocks until the link stops and returns why.
func (l *tunnelLink) Wait() error {
	<-l.done
	return l.err
}

// Close tears the link down.
func (l *tunnelLink) Close() error {
	l.stop(nil)
	return nil
}

// sourceIs reports whether an IP packet's source address equals ip. It handles
// both families, since the tunnel carries both.
func sourceIs(pkt []byte, ip net.IP) bool {
	if len(pkt) == 0 {
		return false
	}
	switch pkt[0] >> 4 {
	case 4:
		v4 := ip.To4()
		return v4 != nil && len(pkt) >= 20 && net.IP(pkt[12:16]).Equal(v4)
	case 6:
		return len(pkt) >= 40 && net.IP(pkt[8:24]).Equal(ip)
	default:
		return false
	}
}

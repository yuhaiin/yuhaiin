package fortinet

// Driving a PPP session over the framed tunnel connection.
//
// Once the HTTPS handshake is done, the TLS stream carries nothing but framed
// PPP: each record is the 6-octet Fortinet header and a bare PPP frame. pppLink
// is the glue between that byte stream and internal/ppp — it reads records and
// splits them (an IP frame to the TUN, a control frame to the PPP state machine),
// and it writes the TUN's outbound packets back out as framed PPP. It serves both
// roles; only the session it drives differs.

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/xen0bit/veepin/internal/ppp"
	"github.com/xen0bit/veepin/internal/vlog"
)

// maxInnerPacket bounds a packet read from the TUN.
const maxInnerPacket = 65535

// pppLink couples a framed net.Conn to a PPP session and a TUN.
type pppLink struct {
	conn   net.Conn
	reader io.Reader // read side; nil means read from conn (a hijacked server conn sets it)
	tun    io.ReadWriteCloser
	logger *vlog.Logger

	// ownsTUN is true for a client, which has the TUN to itself; false for a
	// server link, which shares one TUN across clients and must not close it.
	ownsTUN bool
	// datagram is true when the carrier is DTLS: each datagram holds exactly one
	// framed record, so records are read whole rather than streamed. Over the TLS
	// carrier records are a byte stream and this is false.
	datagram bool
	// assignedSrc, when set, is the only inner source address this link may send.
	// A server sets it so one client cannot inject traffic as another; a client
	// leaves it nil.
	assignedSrc net.IP

	// Exactly one of these drives the control frames.
	client *ppp.Session
	server *ppp.ServerSession

	// alt is a DTLS carrier attached to a link that already has a TLS one. A
	// real client brings DTLS up alongside the tunnel rather than instead of it
	// and then prefers it, so both carry frames for the same PPP session: alt is
	// the egress while it lives, and either read loop feeds the same session.
	// Guarded by writeMu, which is what chooses the egress.
	alt       net.Conn
	writeMu   sync.Mutex // serialises writes to the carrier (PPP negotiation vs the TUN loop)
	done      chan struct{}
	closeOnce sync.Once
	err       error
}

// probe runs PPP's own liveness check over the link's current carrier. Only a
// client link has one to run: a server link answers echoes rather than sending
// them, and it has many peers rather than one.
func (l *pppLink) probe(ctx context.Context) error {
	if l.client == nil {
		return errors.New("fortinet: only a client link probes")
	}
	return l.client.SendEcho(ctx)
}

// rd is the read side of the link.
func (l *pppLink) rd() io.Reader {
	if l.reader != nil {
		return l.reader
	}
	return l.conn
}

// SendPPP writes one PPP frame to the tunnel, wrapped in the Fortinet header. It
// is the ppp.Transport the session calls, and the TUN loop uses it too, so it
// holds the write lock.
//
// A failure of the DTLS carrier is not a failure of the send. The whole point of
// keeping the TLS connection open underneath is that losing UDP costs the
// carrier and not the tunnel, so a write that fails there detaches and goes out
// over TLS instead. Reporting the error would defeat that: tunLoop reads any
// SendPPP error as the link ending, so a single packet unlucky enough to be in
// the TUN loop when the UDP socket died would tear down a tunnel that still has
// a perfectly good carrier. Only a failure of the TLS carrier is fatal.
func (l *pppLink) SendPPP(frame []byte) error {
	rec := EncodeFrame(frame)
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	if alt := l.alt; alt != nil {
		if _, err := alt.Write(rec); err == nil {
			return nil
		}
		l.alt = nil
		// readAlt is still blocked on this conn; closing it is what wakes it, and
		// its own detachDTLS then finds it is no longer the carrier and does
		// nothing. Closing twice is harmless, losing the wake-up would not be.
		_ = alt.Close()
	}
	_, err := l.conn.Write(rec)
	return err
}

// attachDTLS gives an established link a DTLS carrier and makes it the egress.
// The TLS connection stays open underneath: it is the fallback the client keeps
// for exactly this reason, so losing UDP costs a detach, not the tunnel.
func (l *pppLink) attachDTLS(conn net.Conn) {
	l.writeMu.Lock()
	prev := l.alt
	l.alt = conn
	l.writeMu.Unlock()
	if prev != nil {
		// A second DTLS session for the same client supersedes the first.
		_ = prev.Close()
	}
	go l.readAlt(conn)
}

// detachDTLS drops a DTLS carrier, returning the egress to TLS. It is a no-op if
// conn is not the current carrier, so a losing race cannot unseat its successor.
//
// This side's egress recovers at once -- SendPPP falls back to TLS the moment a
// write to the carrier fails. The far end's does not: a datagram sent to a dead
// peer is dropped by the network rather than refused, so it keeps using UDP
// until its own read loop sees the close, and the frames it sends meanwhile are
// lost. That is ordinary datagram loss, which the traffic inside the tunnel
// already copes with -- and it is why the TLS carrier is kept rather than
// replaced, so the loss is a gap rather than the end of the tunnel.
func (l *pppLink) detachDTLS(conn net.Conn) {
	l.writeMu.Lock()
	if l.alt == conn {
		l.alt = nil
	}
	l.writeMu.Unlock()
	_ = conn.Close()
}

// readAlt reads the DTLS carrier's frames into the same PPP session. Its end is
// not the link's end: the TLS carrier is still there, so it detaches instead.
func (l *pppLink) readAlt(conn net.Conn) {
	dgram := make([]byte, maxInnerPacket)
	for {
		n, err := conn.Read(dgram)
		if err != nil {
			l.detachDTLS(conn)
			return
		}
		frame, _, err := ParseFrame(dgram[:n])
		if err != nil {
			// One malformed datagram is not worth the carrier; drop it.
			continue
		}
		if !l.dispatch(frame) {
			return
		}
	}
}

// readLoop reads framed records and dispatches them until the connection ends.
func (l *pppLink) readLoop() {
	var dgram []byte
	if l.datagram {
		dgram = make([]byte, maxInnerPacket)
	}
	for {
		frame, err := l.readFrame(dgram)
		if err != nil {
			l.stop(err)
			return
		}
		if !l.dispatch(frame) {
			return
		}
	}
}

// dispatch routes one PPP frame -- an IP packet to the TUN, anything else to the
// session -- and reports whether the link is still usable.
func (l *pppLink) dispatch(frame []byte) bool {
	if ipPacket, ok := ppp.IsIP(frame); ok {
		if l.assignedSrc != nil && !sourceIs(ipPacket, l.assignedSrc) {
			// A client sending from an address it was not assigned is spoofing;
			// drop it rather than let it reach the shared TUN as another client.
			return true
		}
		if _, err := l.tun.Write(ipPacket); err != nil {
			l.stop(err)
			return false
		}
		return true
	}
	if l.client != nil {
		l.client.Receive(frame)
	} else {
		l.server.Receive(frame)
	}
	return true
}

// readFrame reads one framed record, from the byte stream (TLS) or one whole
// datagram (DTLS). Over DTLS a record must fit a single datagram, which every
// PPP frame does.
func (l *pppLink) readFrame(dgram []byte) ([]byte, error) {
	if !l.datagram {
		return ReadFrame(l.rd())
	}
	n, err := l.rd().Read(dgram)
	if err != nil {
		return nil, err
	}
	frame, _, err := ParseFrame(dgram[:n])
	return frame, err
}

// tunLoop reads outbound IP packets and sends each as a framed PPP IP frame. It
// starts only once the link is up, so it never races the negotiation.
func (l *pppLink) tunLoop() {
	buf := make([]byte, maxInnerPacket)
	for {
		n, err := l.tun.Read(buf)
		if err != nil {
			l.stop(err)
			return
		}
		if err := l.SendPPP(ppp.EncapsulateIP(buf[:n])); err != nil {
			l.stop(err)
			return
		}
	}
}

// stop tears the link down once, recording the first cause. It closes the TUN
// only when it owns it, so a server link ending does not take the shared TUN —
// and every other client — down with it.
func (l *pppLink) stop(cause error) {
	l.closeOnce.Do(func() {
		l.err = cause
		close(l.done)
		l.writeMu.Lock()
		alt := l.alt
		l.alt = nil
		l.writeMu.Unlock()
		if alt != nil {
			_ = alt.Close()
		}
		_ = l.conn.Close()
		if l.ownsTUN && l.tun != nil {
			_ = l.tun.Close()
		}
	})
}

// sourceIs reports whether an IPv4 packet's source address equals ip.
func sourceIs(pkt []byte, ip net.IP) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return false
	}
	v4 := ip.To4()
	return v4 != nil && pkt[12] == v4[0] && pkt[13] == v4[1] && pkt[14] == v4[2] && pkt[15] == v4[3]
}

// Wait blocks until the link stops and returns why.
func (l *pppLink) Wait() error {
	<-l.done
	return l.err
}

// Close tears the link down.
func (l *pppLink) Close() error {
	l.stop(nil)
	return nil
}

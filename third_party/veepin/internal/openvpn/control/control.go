// Package control is OpenVPN's TLS control channel: it turns the lossy UDP
// datagram path into the ordered, reliable byte stream that crypto/tls runs its
// handshake over.
//
// A Channel implements net.Conn. crypto/tls writes handshake records to it and
// reads the peer's back; underneath, each write is chunked into P_CONTROL_V1
// messages numbered by the reliability layer, and each read reassembles the
// in-order payloads the reliability layer delivers. Reliable message 0 is the
// hard-reset that opens the session and carries no TLS bytes; messages 1+ carry
// the handshake and, after it, the key-negotiation exchange.
//
// The Channel does not own the UDP socket — the data channel shares it. Instead
// the caller owns one read loop that demuxes datagrams by opcode, handing
// control packets to Deliver, and supplies a send function the Channel writes
// through. This keeps a single reader on the socket across both channels.
package control

import (
	"crypto/rand"
	"net"
	"os"
	"sync"
	"time"

	"github.com/xen0bit/veepin/internal/openvpn/reliable"
	"github.com/xen0bit/veepin/internal/openvpn/wire"
)

const (
	// maxControlPayload bounds the TLS bytes carried in one control message, so a
	// control packet stays within a conservative UDP MTU after its header. It is
	// well under OpenVPN's default control-channel MTU.
	maxControlPayload = 1200
	// maxACKPerPacket caps the acknowledgements packed into one packet.
	maxACKPerPacket = 4
	// datagramQueue is how many inbound control datagrams buffer between the
	// caller's read loop and the pump; retransmission covers a rare overflow drop.
	datagramQueue = 64
	// inboundQueue is how many delivered TLS payloads buffer for Read. A server's
	// certificate flight is a handful of messages, so this holds a whole flight.
	inboundQueue = 64
)

// Wrapper adds and removes a control channel's static-key protection —
// --tls-auth or --tls-crypt. It is optional: a nil Wrapper is the plain profile.
// Both methods run only on the pump goroutine, so they need no locking of their
// own beyond the send counter.
type Wrapper interface {
	// Wrap protects a marshalled control packet before it is sent.
	Wrap(pkt []byte) ([]byte, error)
	// Unwrap checks and strips protection from an inbound datagram, or returns an
	// error (which drops the datagram).
	Unwrap(datagram []byte) ([]byte, error)
}

// Channel is one OpenVPN control channel: a net.Conn for crypto/tls backed by
// the reliability layer over UDP.
type Channel struct {
	send            func([]byte) error
	wrap            Wrapper
	keyID           uint8
	local           wire.SessionID
	hardResetOpcode uint8 // client- or server-role reset opcode for message 0

	sender    *reliable.Sender
	receiver  *reliable.Receiver
	datagrams chan []byte // inbound control packets from the caller's read loop
	inbound   chan []byte // reassembled TLS payloads awaiting Read
	outbound  chan []byte // TLS write chunks awaiting the send window

	mu        sync.Mutex
	remote    wire.SessionID
	remoteSet bool

	// readRem and readDeadline are touched only by the single TLS goroutine that
	// calls Read/SetDeadline, so they need no lock.
	readRem      []byte
	readDeadline time.Time

	closeOnce sync.Once
	closed    chan struct{}
	errOnce   sync.Once
	err       error
}

// New creates a client-role control channel that transmits through send, tagging
// packets with keyID. It picks a random local session ID, queues the client hard
// reset as reliable message 0, and starts the pump. timeout is the reliability
// retransmit interval (--tls-timeout); zero uses the OpenVPN default. wrap, if
// non-nil, applies --tls-auth/--tls-crypt protection to every control packet. The
// returned Channel is a net.Conn ready for crypto/tls; the caller must route
// inbound control datagrams to Deliver.
func New(send func([]byte) error, keyID uint8, timeout time.Duration, wrap Wrapper) (*Channel, error) {
	return newChannel(send, keyID, timeout, wrap, wire.PControlHardResetClientV2)
}

// NewServer is the server-role counterpart of New: it behaves identically but
// answers with a server hard reset (message 0), the reply to a client's
// PControlHardResetClientV2. The caller creates one per accepted client, after
// the client's hard reset, and runs crypto/tls in server mode over it.
func NewServer(send func([]byte) error, keyID uint8, timeout time.Duration, wrap Wrapper) (*Channel, error) {
	return newChannel(send, keyID, timeout, wrap, wire.PControlHardResetServerV2)
}

func newChannel(send func([]byte) error, keyID uint8, timeout time.Duration, wrap Wrapper, hardReset uint8) (*Channel, error) {
	var sid wire.SessionID
	if _, err := rand.Read(sid[:]); err != nil {
		return nil, err
	}
	c := &Channel{
		send:            send,
		wrap:            wrap,
		keyID:           keyID,
		local:           sid,
		hardResetOpcode: hardReset,
		sender:          reliable.NewSender(0, timeout),
		receiver:        reliable.NewReceiver(),
		datagrams:       make(chan []byte, datagramQueue),
		inbound:         make(chan []byte, inboundQueue),
		outbound:        make(chan []byte),
		closed:          make(chan struct{}),
	}
	// The hard reset is reliable message 0 with no TLS payload.
	c.sender.Queue(nil)
	go c.pump()
	return c, nil
}

// LocalSessionID is the session ID this side chose; the data channel needs it,
// and it is fixed for the connection's life.
func (c *Channel) LocalSessionID() wire.SessionID { return c.local }

// Closed returns a channel that is closed when the control channel is, so a
// caller's background goroutine (e.g. a server's per-client keepalive) can stop
// with it.
func (c *Channel) Closed() <-chan struct{} { return c.closed }

// RemoteSessionID is the peer's session ID, valid once the handshake has begun.
func (c *Channel) RemoteSessionID() (wire.SessionID, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remote, c.remoteSet
}

// Deliver hands an inbound control datagram to the channel. It never blocks: a
// full queue drops the datagram, which the peer's retransmission recovers.
func (c *Channel) Deliver(datagram []byte) {
	pkt := append([]byte(nil), datagram...)
	select {
	case c.datagrams <- pkt:
	case <-c.closed:
	default:
		// Queue full; rely on retransmission.
	}
}

// pump owns the reliability state: it transmits due and standalone-ACK packets,
// accepts inbound datagrams, and pulls TLS write chunks into the send window. It
// is the only goroutine that touches sender and receiver.
func (c *Channel) pump() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		c.transmit(time.Now())

		wait := time.Hour
		if d, ok := c.sender.NextDue(time.Now()); ok {
			wait = d
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)

		// Offer the outbound channel only while the window has room, so a full
		// window applies backpressure to TLS Write rather than overflowing.
		var writes chan []byte
		if c.sender.Ready() {
			writes = c.outbound
		}

		select {
		case <-c.closed:
			return
		case dg := <-c.datagrams:
			c.handleDatagram(dg)
		case chunk := <-writes:
			c.sender.Queue(chunk)
		case <-timer.C:
		}
	}
}

// transmit sends every message the reliability layer says is due, piggybacking
// pending acknowledgements onto the first, and a standalone ACK if there are
// acknowledgements pending with nothing else to send.
func (c *Channel) transmit(now time.Time) {
	due := c.sender.Due(now)

	var acks []uint32
	if c.remoteReady() {
		acks = c.receiver.TakeACKs(maxACKPerPacket)
	}
	for i, m := range due {
		if i == 0 {
			c.sendMessage(m, acks)
			acks = nil
		} else {
			c.sendMessage(m, nil)
		}
	}
	if len(acks) > 0 {
		c.sendACK(acks)
	}
}

// sendMessage encodes and transmits one reliable message, using the hard-reset
// opcode for message 0 and P_CONTROL_V1 for the rest, with any acks attached.
func (c *Channel) sendMessage(m reliable.Message, acks []uint32) {
	opcode := uint8(wire.PControlV1)
	if m.ID == 0 {
		opcode = c.hardResetOpcode
	}
	p := &wire.ControlPacket{
		Opcode:    opcode,
		KeyID:     c.keyID,
		SessionID: c.local,
		PacketID:  m.ID,
		Payload:   m.Payload,
	}
	c.attachACKs(p, acks)
	c.writePacket(p)
}

// sendACK transmits a pure acknowledgement (P_ACK_V1), which carries no message
// ID or payload of its own.
func (c *Channel) sendACK(acks []uint32) {
	p := &wire.ControlPacket{
		Opcode:    wire.PACKV1,
		KeyID:     c.keyID,
		SessionID: c.local,
	}
	c.attachACKs(p, acks)
	c.writePacket(p)
}

// attachACKs adds an acknowledgement array and the remote session ID to a
// packet. An ACK array names whose messages it acknowledges, so it is only valid
// once the peer's session ID is known.
func (c *Channel) attachACKs(p *wire.ControlPacket, acks []uint32) {
	if len(acks) == 0 {
		return
	}
	rsid, ok := c.RemoteSessionID()
	if !ok {
		return
	}
	p.ACKs = acks
	p.RemoteSessionID = rsid
}

func (c *Channel) writePacket(p *wire.ControlPacket) {
	buf := make([]byte, p.MarshalLen())
	out, err := p.Marshal(buf)
	if err != nil {
		c.fail(err)
		return
	}
	if c.wrap != nil {
		out, err = c.wrap.Wrap(out)
		if err != nil {
			c.fail(err)
			return
		}
	}
	if err := c.send(out); err != nil {
		c.fail(err)
	}
}

// handleDatagram processes one inbound control packet: it learns or checks the
// peer's session ID, releases acknowledged messages, and delivers in-order
// payloads to Read. The hard-reset's empty payload is dropped rather than fed to
// TLS.
func (c *Channel) handleDatagram(dg []byte) {
	if c.wrap != nil {
		plain, err := c.wrap.Unwrap(dg)
		if err != nil {
			return // authentication failure or replay: drop, retransmission recovers
		}
		dg = plain
	}
	op, _, ok := wire.Opcode(dg)
	if !ok || !wire.IsControl(op) {
		return
	}
	p, err := wire.ParseControl(dg)
	if err != nil {
		return
	}

	c.mu.Lock()
	if !c.remoteSet {
		c.remote = p.SessionID
		c.remoteSet = true
	} else if p.SessionID != c.remote {
		c.mu.Unlock()
		return // a packet from a different session
	}
	c.mu.Unlock()

	for _, id := range p.ACKs {
		c.sender.Ack(id)
	}
	if p.Opcode == wire.PACKV1 {
		return // pure ack: nothing to deliver
	}
	for _, payload := range c.receiver.Receive(p.PacketID, p.Payload) {
		if len(payload) == 0 {
			continue // the hard reset carries no TLS bytes
		}
		select {
		case c.inbound <- payload:
		case <-c.closed:
			return
		}
	}
}

func (c *Channel) remoteReady() bool {
	_, ok := c.RemoteSessionID()
	return ok
}

// --- net.Conn for crypto/tls ---

// Read returns the next reassembled TLS bytes, blocking until some arrive, the
// read deadline passes, or the channel closes.
func (c *Channel) Read(p []byte) (int, error) {
	if len(c.readRem) > 0 {
		n := copy(p, c.readRem)
		c.readRem = c.readRem[n:]
		return n, nil
	}
	var timeout <-chan time.Time
	if !c.readDeadline.IsZero() {
		t := time.NewTimer(time.Until(c.readDeadline))
		defer t.Stop()
		timeout = t.C
	}
	select {
	case payload := <-c.inbound:
		n := copy(p, payload)
		if n < len(payload) {
			c.readRem = payload[n:]
		}
		return n, nil
	case <-timeout:
		return 0, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, c.error()
	}
}

// Write chunks TLS bytes into control-message-sized pieces and hands them to the
// pump, blocking on the send window when it is full.
func (c *Channel) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), maxControlPayload)
		chunk := append([]byte(nil), p[:n]...)
		select {
		case c.outbound <- chunk:
		case <-c.closed:
			return written, c.error()
		}
		p = p[n:]
		written += n
	}
	return written, nil
}

// Close stops the pump. It does not close the shared UDP socket, which the data
// channel keeps using.
func (c *Channel) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *Channel) SetDeadline(t time.Time) error      { c.readDeadline = t; return nil }
func (c *Channel) SetReadDeadline(t time.Time) error  { c.readDeadline = t; return nil }
func (c *Channel) SetWriteDeadline(t time.Time) error { return nil }
func (c *Channel) LocalAddr() net.Addr                { return controlAddr{} }
func (c *Channel) RemoteAddr() net.Addr               { return controlAddr{} }

// fail records the first error and closes the channel, so a blocked Read or
// Write returns it rather than a generic closed error.
func (c *Channel) fail(err error) {
	c.errOnce.Do(func() { c.err = err })
	c.Close()
}

func (c *Channel) error() error {
	if c.err != nil {
		return c.err
	}
	return net.ErrClosed
}

// controlAddr is a placeholder net.Addr; crypto/tls needs the accessors but does
// not use the values.
type controlAddr struct{}

func (controlAddr) Network() string { return "openvpn-control" }
func (controlAddr) String() string  { return "openvpn-control" }

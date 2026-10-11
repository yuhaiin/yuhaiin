package l2tpv3

import (
	"net"
	"sync"
	"time"
)

// The quiescent control connection: RFC 3931's reliable transport carrying
// nothing but HELLO keepalives.
//
//	   us                                   peer
//	    |------- HELLO   Ns=0 Nr=0 --------->|
//	    |<------ ACK     Ns=0 Nr=1 ----------|
//	    |<------ HELLO   Ns=0 Nr=1 ----------|
//	    |------- ACK     Ns=1 Nr=1 --------->|
//
// Why it exists: a static pseudowire sends nothing of its own, so a dead peer
// is indistinguishable from an idle one. HELLO makes silence mean something,
// which is what turns Pump.IdleFor from a guess into a liveness signal.
//
// The sequence-number rules are the part worth stating, because they are not
// symmetric with what a reader expects:
//
//   - Ns is OUR next send sequence. It advances only on a message that occupies
//     a sequence number -- HELLO does, ACK does NOT (RFC 3931 section 4.2).
//     Advancing it for an ACK desynchronises the peer's window permanently.
//   - Nr is the next Ns we expect FROM the peer, so it acknowledges everything
//     below it.

const (
	// defaultHelloInterval is how often we send a HELLO when the connection is
	// otherwise silent. RFC 3931 suggests 60s; a shorter default detects a dead
	// peer sooner and costs one small datagram.
	defaultHelloInterval = 30 * time.Second
	// retransmitInterval is the first retransmission delay; it doubles up to
	// maxRetransmitInterval (RFC 3931 section 4.2 recommends exponential backoff).
	retransmitInterval    = 1 * time.Second
	maxRetransmitInterval = 8 * time.Second
	// maxRetransmits is how many times an unacknowledged message is resent
	// before the control connection is declared dead.
	maxRetransmits = 5
)

// ControlConfig configures the quiescent control connection.
type ControlConfig struct {
	// LocalCCID is the Control Connection ID we chose; the peer puts it on
	// messages it sends us, and we verify it. Same receiver-chooses convention
	// as the data cookie.
	LocalCCID uint32
	// RemoteCCID is the peer's; we put it on messages we send.
	RemoteCCID uint32
	// HelloInterval is the keepalive period (default 30s). Negative disables
	// sending HELLOs while still answering the peer's.
	HelloInterval time.Duration
	// PeerAddr is where control messages go. A server leaves it nil and learns
	// it from the first message that verifies.
	PeerAddr *net.UDPAddr
}

// ControlConn runs one quiescent control connection.
//
// It owns no socket: the caller feeds it inbound datagrams and supplies a
// Sender, exactly as Pump does, so the same connection runs over a real socket
// or a test pipe.
type ControlConn struct {
	cfg  ControlConfig
	send Sender

	mu       sync.Mutex
	ns       uint16 // our next send sequence
	nr       uint16 // next Ns expected from the peer
	inFlight *pendingMsg
	closed   bool

	// lastInbound is when a control message last verified, in unix nanos.
	lastInbound int64
	// onDead is called once when the peer stops acknowledging.
	onDead func()

	buf  []byte // reusable encode buffer, guarded by mu
	stop chan struct{}
	wg   sync.WaitGroup
}

// pendingMsg is a sent message awaiting acknowledgement.
type pendingMsg struct {
	ns      uint16
	msgType uint16
	tries   int
	backoff time.Duration
	sentAt  time.Time
}

// NewControlConn creates a control connection. Run starts it.
func NewControlConn(cfg ControlConfig, send Sender, onDead func()) *ControlConn {
	if cfg.HelloInterval == 0 {
		cfg.HelloInterval = defaultHelloInterval
	}
	return &ControlConn{
		cfg:         cfg,
		send:        send,
		onDead:      onDead,
		buf:         make([]byte, 0, 256),
		stop:        make(chan struct{}),
		lastInbound: time.Now().UnixNano(),
	}
}

// Run drives the keepalive and retransmission timers until Close.
func (c *ControlConn) Run() {
	c.wg.Add(1)
	defer c.wg.Done()

	// A short tick drives both jobs; the work is a couple of comparisons and a
	// datagram at most every HelloInterval, so the cost is nil.
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()

	lastHello := time.Now()
	for {
		select {
		case <-c.stop:
			return
		case now := <-tick.C:
			if c.retransmitDue(now) {
				return // declared dead
			}
			if c.cfg.HelloInterval > 0 && now.Sub(lastHello) >= c.cfg.HelloInterval {
				lastHello = now
				c.sendHello()
			}
		}
	}
}

// retransmitDue resends an unacknowledged message when its backoff expires,
// and reports whether the connection has been declared dead.
func (c *ControlConn) retransmitDue(now time.Time) bool {
	c.mu.Lock()
	p := c.inFlight
	if p == nil || now.Sub(p.sentAt) < p.backoff {
		c.mu.Unlock()
		return false
	}
	if p.tries >= maxRetransmits {
		c.closed = true
		c.mu.Unlock()
		if c.onDead != nil {
			c.onDead()
		}
		return true
	}
	p.tries++
	p.backoff = min(p.backoff*2, maxRetransmitInterval)
	p.sentAt = now
	pkt := c.encode(p.ns, c.nr, p.msgType, nil)
	peer := c.cfg.PeerAddr
	c.mu.Unlock()

	if peer != nil {
		c.send(pkt, peer)
	}
	return false
}

// sendHello transmits a keepalive, if none is already awaiting acknowledgement.
// Queueing a second would consume a sequence number the peer has not caught up
// to, which is how a keepalive turns into a stall.
func (c *ControlConn) sendHello() {
	c.mu.Lock()
	if c.closed || c.inFlight != nil || c.cfg.PeerAddr == nil {
		c.mu.Unlock()
		return
	}
	ns := c.ns
	c.ns++ // HELLO occupies a sequence number; ACK does not.
	c.inFlight = &pendingMsg{ns: ns, msgType: msgHello, backoff: retransmitInterval, sentAt: time.Now()}
	pkt := c.encode(ns, c.nr, msgHello, nil)
	peer := c.cfg.PeerAddr
	c.mu.Unlock()

	c.send(pkt, peer)
}

// encode builds a control message into the reusable buffer. The caller holds
// c.mu, which is what makes the shared buffer safe.
func (c *ControlConn) encode(ns, nr, msgType uint16, extra []byte) []byte {
	c.buf = AppendControl(c.buf[:0], c.cfg.RemoteCCID, ns, nr, msgType, extra)
	// The send may outlive the lock, so hand out a copy rather than the shared
	// buffer. Control traffic is one small datagram per interval; this is not a
	// hot path and correctness beats saving the allocation.
	out := make([]byte, len(c.buf))
	copy(out, c.buf)
	return out
}

// HandleControl processes one inbound control datagram. from is its source,
// which becomes the reply address once the message verifies.
func (c *ControlConn) HandleControl(pkt []byte, from *net.UDPAddr) {
	m, err := ParseControl(pkt)
	if err != nil {
		return
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	// The CCID must be the one WE chose. Accepting any value would let an
	// off-path sender reset our sequence state.
	if m.CCID != c.cfg.LocalCCID {
		c.mu.Unlock()
		return
	}

	// Nr acknowledges everything below it, so an in-flight message whose
	// sequence has been passed is done.
	if c.inFlight != nil && seqLess(c.inFlight.ns, m.Nr) {
		c.inFlight = nil
	}
	c.lastInbound = time.Now().UnixNano()
	if from != nil {
		c.cfg.PeerAddr = from
	}

	var reply []byte
	peer := c.cfg.PeerAddr
	switch m.Type {
	case msgAck:
		// Acknowledgement only: it occupies no sequence number, so nothing to
		// advance and nothing to answer.
	case msgStopCCN:
		c.closed = true
		c.mu.Unlock()
		if c.onDead != nil {
			c.onDead()
		}
		return
	default:
		// HELLO, or anything else that occupies a sequence number. Answer only
		// the one we are expecting; a retransmission of an older message gets
		// the same ack again, and a future one is dropped as out of order.
		if m.Ns == c.nr {
			c.nr++
			reply = c.encode(c.ns, c.nr, msgAck, nil)
		} else if seqLess(m.Ns, c.nr) {
			reply = c.encode(c.ns, c.nr, msgAck, nil)
		}
	}
	c.mu.Unlock()

	if reply != nil && peer != nil {
		c.send(reply, peer)
	}
}

// IdleFor reports how long since a control message last verified.
func (c *ControlConn) IdleFor() time.Duration {
	c.mu.Lock()
	t := c.lastInbound
	c.mu.Unlock()
	return time.Since(time.Unix(0, t))
}

// Close stops the connection, sending StopCCN if the peer is known.
func (c *ControlConn) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	var bye []byte
	peer := c.cfg.PeerAddr
	if peer != nil {
		bye = c.encode(c.ns, c.nr, msgStopCCN, nil)
	}
	c.mu.Unlock()

	if bye != nil {
		c.send(bye, peer)
	}
	close(c.stop)
	c.wg.Wait()
}

// seqLess compares L2TP sequence numbers, which wrap at 16 bits.
func seqLess(a, b uint16) bool { return int16(a-b) < 0 }

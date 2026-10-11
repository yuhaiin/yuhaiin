package l2tp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Role selects which end of the tunnel this is: the LAC places the call
// (client/initiator), the LNS accepts it (server/responder).
type Role int

const (
	// RoleLAC is the initiator: it opens the control connection with SCCRQ and
	// places the incoming call with ICRQ.
	RoleLAC Role = iota
	// RoleLNS is the responder: it answers SCCRQ with SCCRP and the call with ICRP.
	RoleLNS
)

// Handler receives a tunnel's lifecycle events. The l2tp session implements it:
// on SessionUp it starts PPP, DataFrame carries an inbound PPP frame (an IP
// packet for the TUN or an LCP/CHAP/IPCP control frame), and Closed reports
// teardown.
type Handler interface {
	SessionUp()
	DataFrame(frame []byte)
	Closed(err error)
}

// Defaults for the control channel. The retransmit cadence and cap bound the
// handshake; a reliable path (loopback, or an ESP SA over a healthy link) needs
// no retries, but a lossy path must not stall forever.
const (
	defaultHostName    = "veepin"
	defaultWindowSize  = 4
	retransmitInterval = 1 * time.Second
	maxRetransmits     = 5
)

// handshake states, progressing in message order for each role.
type state int

const (
	stateIdle      state = iota
	stateWaitSCCRP       // LAC: sent SCCRQ
	stateWaitICRP        // LAC: sent ICRQ
	stateWaitSCCCN       // LNS: sent SCCRP
	stateWaitICRQ        // LNS: got SCCCN
	stateWaitICCN        // LNS: sent ICRP
	stateEstablished
	stateClosed
)

// pending is one control message awaiting acknowledgement, kept so it can be
// rebuilt (with a current Nr) and retransmitted.
type pending struct {
	ns        uint16
	sessionID uint16
	avps      []byte
}

// Tunnel is one L2TP control connection carrying a single session, driving a PPP
// link over it. It is transport-neutral: it emits datagrams through send and is
// fed inbound datagrams via HandleInbound. The control channel (Ns/Nr, retransmit)
// is serialised under mu; the data path reads the peer IDs lock-free once the
// session is up.
type Tunnel struct {
	role     Role
	send     func([]byte) error
	h        Handler
	hostName string

	// Peer-assigned IDs addressed outbound messages; written once during the
	// handshake, then read lock-free by the data path.
	peerTunnelID  atomic.Uint32
	peerSessionID atomic.Uint32
	// closedFlag lets the lock-free data path (SendPPP) short-circuit without
	// racing the control channel's state field.
	closedFlag atomic.Bool

	mu             sync.Mutex
	state          state
	localTunnelID  uint16
	localSessionID uint16

	ns, nr   uint16
	unacked  []pending
	timer    *time.Timer
	retries  int
	closeErr error

	// helloNs is the sequence number of the HELLO a probe is waiting on, and
	// helloWait the channel closed when the peer acknowledges it (or the
	// tunnel dies). One waiter rather than a registry, because a probe is the
	// only caller that needs to know a specific message landed -- every other
	// control message is driven by the state machine, which learns the same
	// thing from the reply it was expecting anyway.
	helloNs   uint16
	helloWait chan struct{}
}

// NewTunnel builds a tunnel for the given role. The LAC must call Start to open
// the control connection; the LNS starts passively on the first inbound SCCRQ.
func NewTunnel(role Role, send func([]byte) error, h Handler) *Tunnel {
	return &Tunnel{
		role:           role,
		send:           send,
		h:              h,
		hostName:       defaultHostName,
		localTunnelID:  randID(),
		localSessionID: randID(),
	}
}

// LocalTunnelID is this end's Assigned Tunnel ID — the value the peer places in
// the header of packets it sends us, so a server demultiplexes inbound datagrams
// by it.
func (t *Tunnel) LocalTunnelID() uint16 { return t.localTunnelID }

// Start opens the control connection (LAC only): it sends SCCRQ.
func (t *Tunnel) Start() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.role != RoleLAC || t.state != stateIdle {
		return
	}
	t.sendSCCRQ()
	t.state = stateWaitSCCRP
}

// SendPPP wraps a PPP frame in an L2TP data message and sends it. It implements
// ppp.Transport, so both the PPP control machinery and the IP data path (via
// ppp.EncapsulateIP) reach the peer through it. It is safe to call concurrently
// with the control channel: data messages are unsequenced and read only the
// peer IDs, which are fixed by the time the session is up.
func (t *Tunnel) SendPPP(frame []byte) error {
	if t.closedFlag.Load() {
		return fmt.Errorf("l2tp: tunnel closed")
	}
	tid := uint16(t.peerTunnelID.Load())
	sid := uint16(t.peerSessionID.Load())
	return t.send(marshalData(tid, sid, frame))
}

// HandleInbound dispatches one received L2TP datagram: data messages hand their
// PPP payload straight to the handler, control messages drive the reliable state
// machine.
func (t *Tunnel) HandleInbound(pkt []byte) {
	h, err := parseHeader(pkt)
	if err != nil {
		return
	}
	if !h.isControl {
		if len(h.payload) > 0 {
			t.h.DataFrame(h.payload)
		}
		return
	}
	t.handleControl(h)
}

// Close tears the tunnel down, best-effort notifying the peer with CDN/StopCCN.
func (t *Tunnel) Close() { t.fail(nil) }

func (t *Tunnel) handleControl(h header) {
	var (
		up     bool
		closed bool
		cerr   error
	)
	t.mu.Lock()
	if t.state == stateClosed {
		t.mu.Unlock()
		return
	}
	// The peer's Nr acknowledges everything we sent below it.
	t.purgeAcked(h.nr)

	avps, err := parseAVPs(h.payload)
	if err != nil {
		t.mu.Unlock()
		return
	}
	// A Zero-Length Body message is a pure acknowledgement: purging above is all
	// it does.
	if len(avps) == 0 {
		t.mu.Unlock()
		return
	}
	// Reliable, in-order delivery: only the next expected message advances state;
	// an old duplicate is re-acknowledged, a future one is dropped to be
	// retransmitted by the peer.
	if h.ns != t.nr {
		if seqLess(h.ns, t.nr) {
			t.sendZLB()
		}
		t.mu.Unlock()
		return
	}
	t.nr++

	prevNs := t.ns
	up, closed, cerr = t.dispatch(avps)
	// If dispatch queued no control message, the peer's message is still
	// unacknowledged; send a bare ZLB ack.
	if t.ns == prevNs && !closed {
		t.sendZLB()
	}
	t.mu.Unlock()

	// Invoke handler callbacks outside the lock: SessionUp starts PPP, which
	// re-enters SendPPP (which does not take mu, but keeping callbacks lock-free
	// avoids any handler reaching back into the control channel from deadlocking).
	if up {
		t.h.SessionUp()
	}
	if closed {
		t.finishClose(cerr)
	}
}

// dispatch handles one in-order control message by type, per role, and reports
// whether the session just came up or the tunnel was torn down.
func (t *Tunnel) dispatch(avps []avp) (up, closed bool, cerr error) {
	mt, ok := messageType(avps)
	if !ok {
		return false, false, nil
	}
	switch mt {
	case msgStopCCN:
		return false, true, fmt.Errorf("l2tp: peer sent StopCCN")
	case msgCDN:
		return false, true, fmt.Errorf("l2tp: peer disconnected the call")
	case msgHELLO:
		return false, false, nil // keepalive; the ZLB ack suffices
	}
	switch t.role {
	case RoleLAC:
		return t.dispatchLAC(mt, avps)
	default:
		return t.dispatchLNS(mt, avps)
	}
}

func (t *Tunnel) dispatchLAC(mt uint16, avps []avp) (up, closed bool, cerr error) {
	switch {
	case mt == msgSCCRP && t.state == stateWaitSCCRP:
		pid, ok := findUint16(avps, avpAssignedTunnelID)
		if !ok || pid == 0 {
			return false, true, fmt.Errorf("l2tp: SCCRP without Assigned Tunnel ID")
		}
		t.peerTunnelID.Store(uint32(pid))
		t.sendSCCCN()
		t.sendICRQ()
		t.state = stateWaitICRP
	case mt == msgICRP && t.state == stateWaitICRP:
		sid, ok := findUint16(avps, avpAssignedSessionID)
		if !ok || sid == 0 {
			return false, true, fmt.Errorf("l2tp: ICRP without Assigned Session ID")
		}
		t.peerSessionID.Store(uint32(sid))
		t.sendICCN()
		t.state = stateEstablished
		return true, false, nil
	}
	return false, false, nil
}

func (t *Tunnel) dispatchLNS(mt uint16, avps []avp) (up, closed bool, cerr error) {
	switch {
	case mt == msgSCCRQ && t.state == stateIdle:
		pid, ok := findUint16(avps, avpAssignedTunnelID)
		if !ok || pid == 0 {
			return false, true, fmt.Errorf("l2tp: SCCRQ without Assigned Tunnel ID")
		}
		t.peerTunnelID.Store(uint32(pid))
		t.sendSCCRP()
		t.state = stateWaitSCCCN
	case mt == msgSCCCN && t.state == stateWaitSCCCN:
		t.state = stateWaitICRQ
	case mt == msgICRQ && t.state == stateWaitICRQ:
		sid, ok := findUint16(avps, avpAssignedSessionID)
		if !ok || sid == 0 {
			return false, true, fmt.Errorf("l2tp: ICRQ without Assigned Session ID")
		}
		t.peerSessionID.Store(uint32(sid))
		t.sendICRP()
		t.state = stateWaitICCN
	case mt == msgICCN && t.state == stateWaitICCN:
		t.state = stateEstablished
		return true, false, nil
	}
	return false, false, nil
}

// --- control message builders (called under mu) ---

func (t *Tunnel) sendSCCRQ() {
	var b avpBuilder
	b.addUint16(avpMessageType, msgSCCRQ)
	b.add(avpProtocolVersion, []byte{1, 0})
	b.addUint32(avpFramingCapabilities, 0x00000003) // async | sync
	b.add(avpHostName, []byte(t.hostName))
	b.addUint16(avpAssignedTunnelID, t.localTunnelID)
	b.addUint16(avpReceiveWindowSize, defaultWindowSize)
	t.queueControl(0, b.bytes())
}

func (t *Tunnel) sendSCCRP() {
	var b avpBuilder
	b.addUint16(avpMessageType, msgSCCRP)
	b.add(avpProtocolVersion, []byte{1, 0})
	b.addUint32(avpFramingCapabilities, 0x00000003)
	b.add(avpHostName, []byte(t.hostName))
	b.addUint16(avpAssignedTunnelID, t.localTunnelID)
	b.addUint16(avpReceiveWindowSize, defaultWindowSize)
	t.queueControl(0, b.bytes())
}

func (t *Tunnel) sendSCCCN() {
	var b avpBuilder
	b.addUint16(avpMessageType, msgSCCCN)
	t.queueControl(0, b.bytes())
}

func (t *Tunnel) sendICRQ() {
	var b avpBuilder
	b.addUint16(avpMessageType, msgICRQ)
	b.addUint16(avpAssignedSessionID, t.localSessionID)
	b.addUint32(avpCallSerialNumber, uint32(t.localSessionID))
	t.queueControl(0, b.bytes())
}

func (t *Tunnel) sendICRP() {
	var b avpBuilder
	b.addUint16(avpMessageType, msgICRP)
	b.addUint16(avpAssignedSessionID, t.localSessionID)
	// Addressed to the peer's assigned session ID once known.
	t.queueControl(uint16(t.peerSessionID.Load()), b.bytes())
}

func (t *Tunnel) sendICCN() {
	var b avpBuilder
	b.addUint16(avpMessageType, msgICCN)
	b.addUint32(avpTxConnectSpeed, 100000000)
	b.addUint32(avpFramingType, 0x00000001) // sync framing
	t.queueControl(uint16(t.peerSessionID.Load()), b.bytes())
}

// ErrTunnelClosed reports a probe on a tunnel that is no longer up.
var ErrTunnelClosed = errors.New("l2tp: tunnel is closed")

// SendHello sends a HELLO and waits for the peer to acknowledge it.
//
// HELLO is L2TP's keepalive (RFC 2661 section 6.5) and it is the one control
// message with no reply of its own: the peer answers it with the ZLB
// acknowledgement the reliable control channel requires of every message, and
// that acknowledgement is the entire liveness proof. So this does not wait for
// an inbound message type -- it waits for its own Ns to leave the unacked
// window, which is what purgeAcked does when the ZLB arrives.
//
// This end has always answered a peer's HELLO and never sent one, which meant
// an L2TP tunnel whose ESP transport had gone quiet stayed up forever with
// nothing crossing it. The retransmit timer would have noticed -- it fails the
// tunnel after maxRetransmits -- but only if something had been queued for it
// to retransmit, and on an idle tunnel nothing ever is.
func (t *Tunnel) SendHello(ctx context.Context) error {
	t.mu.Lock()
	if t.state == stateClosed {
		t.mu.Unlock()
		return ErrTunnelClosed
	}
	if t.helloWait != nil {
		// A probe is already outstanding. Wait on that one rather than
		// queueing a second: the monitor's interval can outpace a lossy path,
		// and one HELLO per outstanding probe is what the retransmit timer is
		// already sized for.
		wait := t.helloWait
		t.mu.Unlock()
		return t.awaitHello(ctx, wait)
	}
	wait := make(chan struct{})
	t.helloWait, t.helloNs = wait, t.ns
	var b avpBuilder
	b.addUint16(avpMessageType, msgHELLO)
	t.queueControl(0, b.bytes())
	t.mu.Unlock()
	return t.awaitHello(ctx, wait)
}

// awaitHello blocks until the HELLO is acknowledged, the tunnel dies, or ctx
// runs out. A closed tunnel releases the channel too, so the three cases are
// distinguished by re-reading the state rather than by which channel fired.
func (t *Tunnel) awaitHello(ctx context.Context, wait <-chan struct{}) error {
	select {
	case <-wait:
		if t.closedFlag.Load() {
			return ErrTunnelClosed
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// queueControl assigns the next Ns, records the message for retransmission, and
// sends it. Called under mu.
func (t *Tunnel) queueControl(sessionID uint16, avps []byte) {
	p := pending{ns: t.ns, sessionID: sessionID, avps: avps}
	t.unacked = append(t.unacked, p)
	t.ns++
	_ = t.send(t.buildControl(p))
	t.armTimer()
}

// buildControl renders a pending control message with the current Nr.
func (t *Tunnel) buildControl(p pending) []byte {
	return marshalControl(uint16(t.peerTunnelID.Load()), p.sessionID, p.ns, t.nr, p.avps)
}

// sendZLB emits a Zero-Length Body acknowledgement carrying the current Nr. It
// consumes no Ns and is never retransmitted.
func (t *Tunnel) sendZLB() {
	_ = t.send(marshalControl(uint16(t.peerTunnelID.Load()), 0, t.ns, t.nr, nil))
}

// purgeAcked drops unacked messages the peer's Nr covers, and stops the timer
// once the window is empty. Called under mu.
func (t *Tunnel) purgeAcked(peerNr uint16) {
	kept := t.unacked[:0]
	for _, p := range t.unacked {
		if seqLess(p.ns, peerNr) {
			if t.helloWait != nil && p.ns == t.helloNs {
				close(t.helloWait)
				t.helloWait = nil
			}
			continue // acknowledged
		}
		kept = append(kept, p)
	}
	t.unacked = kept
	if len(t.unacked) == 0 {
		t.retries = 0
		if t.timer != nil {
			t.timer.Stop()
			t.timer = nil
		}
	}
}

func (t *Tunnel) armTimer() {
	if t.timer != nil {
		return
	}
	t.timer = time.AfterFunc(retransmitInterval, t.onRetransmit)
}

func (t *Tunnel) onRetransmit() {
	t.mu.Lock()
	t.timer = nil
	if t.state == stateClosed || len(t.unacked) == 0 {
		t.mu.Unlock()
		return
	}
	t.retries++
	if t.retries > maxRetransmits {
		t.mu.Unlock()
		t.finishClose(fmt.Errorf("l2tp: control channel timed out"))
		return
	}
	for _, p := range t.unacked {
		_ = t.send(t.buildControl(p))
	}
	t.timer = time.AfterFunc(retransmitInterval, t.onRetransmit)
	t.mu.Unlock()
}

// fail closes the tunnel from any goroutine, notifying the handler once.
func (t *Tunnel) fail(err error) {
	t.mu.Lock()
	if t.state == stateClosed {
		t.mu.Unlock()
		return
	}
	t.mu.Unlock()
	t.finishClose(err)
}

// finishClose transitions to closed, stops the timer, and notifies the handler
// exactly once. Safe to call with or without mu held elsewhere because it
// re-checks state under the lock.
func (t *Tunnel) finishClose(err error) {
	t.mu.Lock()
	if t.state == stateClosed {
		t.mu.Unlock()
		return
	}
	t.state = stateClosed
	t.closedFlag.Store(true)
	t.closeErr = err
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
	// A probe blocked on an acknowledgement that is never coming is released
	// here rather than left to its context deadline, so a tunnel that has
	// already declared itself dead does not also cost the caller a timeout.
	if t.helloWait != nil {
		close(t.helloWait)
		t.helloWait = nil
	}
	t.mu.Unlock()
	t.h.Closed(err)
}

// seqLess reports whether sequence a precedes b in the 16-bit wrapping space.
func seqLess(a, b uint16) bool { return int16(a-b) < 0 }

// randID returns a nonzero random 16-bit identifier for a tunnel or session.
func randID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	id := binary.BigEndian.Uint16(b[:])
	if id == 0 {
		id = 1
	}
	return id
}

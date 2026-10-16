package lightweight

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight/congestion"
)

type TCPState string

const (
	SynSent     TCPState = "SYN-SENT"
	SynReceived TCPState = "SYN-RECEIVED"
	Established TCPState = "ESTABLISHED"
	FinWait1    TCPState = "FIN-WAIT-1"
	FinWait2    TCPState = "FIN-WAIT-2"
	CloseWait   TCPState = "CLOSE-WAIT"
	Closing     TCPState = "CLOSING"
	LastAck     TCPState = "LAST-ACK"
	TimeWait    TCPState = "TIME-WAIT"
	Closed      TCPState = "CLOSED"
)

type TCPListener struct {
	stack     *Stack
	local     netip.AddrPort
	mu        sync.Mutex
	closed    bool
	ready     chan *TCPConn
	done      chan struct{}
	dualStack bool
}

var _ net.Listener = (*TCPListener)(nil)

// A zero AddrPort is a transparent listener for any destination. An unspecified
// address listens on that family. A valid address with port zero selects an
// ephemeral port. This is an IP-only API.
func (s *Stack) ListenTCP(local netip.AddrPort) (*TCPListener, error) {
	return s.listenTCP(local, false)
}

// ListenDualTCP binds one wildcard listener for both IPv4 and IPv6 connections.
func (s *Stack) ListenDualTCP(port uint16) (*TCPListener, error) {
	return s.listenTCP(netip.AddrPortFrom(netip.IPv6Unspecified(), port), true)
}

func (s *Stack) listenTCP(local netip.AddrPort, dual bool) (*TCPListener, error) {
	if local.IsValid() && (local.Addr().Is4In6() || local.Addr().Zone() != "" || local.Addr().IsMulticast() || !local.Addr().IsUnspecified() && !s.local(local.Addr()) && !s.config.Promiscuous) {
		return nil, ErrMalformed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed() {
		return nil, net.ErrClosed
	}
	if len(s.listeners) >= 1024 {
		return nil, ErrLimit
	}
	if local.IsValid() && local.Port() == 0 {
		found := false
		for range 16384 {
			local = netip.AddrPortFrom(local.Addr(), s.port())
			if !s.tcpListenerBound(local, dual) {
				found = true
				break
			}
		}
		if !found {
			return nil, ErrLimit
		}
	} else if s.tcpListenerBound(local, dual) {
		return nil, errors.New("lightweight: TCP listener already exists")
	}
	l := &TCPListener{stack: s, local: local, ready: make(chan *TCPConn, 128), done: make(chan struct{}), dualStack: dual}
	s.listeners[local] = l
	return l, nil
}

func (s *Stack) tcpListenerBound(a netip.AddrPort, dual bool) bool {
	if !a.IsValid() {
		return s.listeners[a] != nil
	}
	for k, l := range s.listeners {
		if k.IsValid() && k.Port() == a.Port() && (dual || l.dualStack || k.Addr().Is4() == a.Addr().Is4() && (k.Addr() == a.Addr() || k.Addr().IsUnspecified() || a.Addr().IsUnspecified())) {
			return true
		}
	}
	return false
}
func (l *TCPListener) Accept() (net.Conn, error) {
	for {
		select {
		case <-l.done:
			return nil, net.ErrClosed
		case <-l.stack.done:
			return nil, net.ErrClosed
		case c := <-l.ready:
			c.mu.Lock()
			ok := c.state != Closed
			c.mu.Unlock()
			if ok {
				return c, nil
			}
		}
	}
}
func (l *TCPListener) Addr() net.Addr { return net.TCPAddrFromAddrPort(l.local) }
func (l *TCPListener) Close() error {
	l.stack.mu.Lock()
	if l.stack.listeners[l.local] == l {
		delete(l.stack.listeners, l.local)
	}
	l.stack.mu.Unlock()
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	close(l.done)
	l.mu.Unlock()
	for {
		select {
		case c := <-l.ready:
			c.abort(net.ErrClosed)
		default:
			return nil
		}
	}
}
func (l *TCPListener) deliver(c *TCPConn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.stack.closed() {
		return false
	}
	select {
	case l.ready <- c:
		return true
	default:
		return false
	}
}

func (s *Stack) listener(dst netip.AddrPort) *TCPListener {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l := s.listeners[dst]; l != nil {
		return l
	}
	anyAddr := netip.IPv6Unspecified()
	if dst.Addr().Is4() {
		anyAddr = netip.IPv4Unspecified()
	}
	if l := s.listeners[netip.AddrPortFrom(anyAddr, dst.Port())]; l != nil {
		return l
	}
	if dst.Addr().Is4() {
		if l := s.listeners[netip.AddrPortFrom(netip.IPv6Unspecified(), dst.Port())]; l != nil && l.dualStack {
			return l
		}
	}
	return s.listeners[netip.AddrPort{}]
}
func (s *Stack) newTCP(k flowKey, state TCPState) (*TCPConn, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	iss := binary.BigEndian.Uint32(b[:])
	mss := s.config.MTU - 40
	if k.local.Addr().Is6() {
		mss -= 20
	}
	// The IPv4/IPv6 defaults apply until the peer advertises MSS.
	peerMSS := 536
	if k.local.Addr().Is6() {
		peerMSS = 1220
	}
	cc, err := congestion.New(s.config.CongestionControl, congestion.Config{MSS: uint64(min(mss, peerMSS)), MaxWindow: uint64(s.config.SendBuffer)})
	if err != nil {
		return nil, err
	}
	c := &TCPConn{stack: s, key: k, state: state, iss: iss, sndUna: iss, sndNxt: iss, sndEnd: iss, mss: min(mss, peerMSS), pathMSS: mss, peerScale: -1, receiveLimit: s.config.ReceiveBuffer, rto: time.Second, controller: cc, born: time.Now(), lastActive: time.Now()}
	for (s.config.MaxReceiveBuffer>>c.ownScale) > 65535 && c.ownScale < 14 {
		c.ownScale++
	}
	c.job = timerJob{index: -1, run: c.onTimer}
	return c, nil
}
func (s *Stack) DialContextTCP(ctx context.Context, remote netip.AddrPort) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !remote.IsValid() || remote.Port() == 0 || remote.Addr().IsUnspecified() || remote.Addr().IsMulticast() || remote.Addr().Is4In6() || remote.Addr().Zone() != "" {
		return nil, ErrMalformed
	}
	src, err := s.source(remote.Addr())
	if err != nil {
		return nil, err
	}
	var c *TCPConn
	for range 16384 {
		c, err = s.newTCP(flowKey{netip.AddrPortFrom(src, s.port()), remote}, SynSent)
		if err != nil {
			return nil, err
		}
		if err = s.add(c); err == nil {
			break
		}
		if errors.Is(err, ErrLimit) || errors.Is(err, net.ErrClosed) {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.enqueueControl(flagSYN)
	c.pump(time.Now())
	c.mu.Unlock()
	stop := context.AfterFunc(ctx, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.state == SynSent || c.state == SynReceived {
			c.finish(ctx.Err())
		}
	})
	defer stop()
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.state == SynSent || c.state == SynReceived {
		ch := watch(&c.changed)
		c.mu.Unlock()
		err = waitSocket(ch, s.done, time.Time{})
		c.mu.Lock()
		if err != nil && c.state != Closed {
			c.finish(err)
		}
	}
	if ctx.Err() != nil {
		c.finish(ctx.Err())
		return nil, ctx.Err()
	}
	if c.state == Closed {
		return nil, c.errorLocked()
	}
	return c, nil
}

func (s *Stack) handleTCP(p Packet) {
	b := p.Payload
	off := int(b[12]>>4) * 4
	opts, err := parseTCPOptions(b[20:off])
	if err != nil {
		s.drops.Add(1)
		return
	}
	k := flowKey{netip.AddrPortFrom(p.Destination, binary.BigEndian.Uint16(b[2:4])), netip.AddrPortFrom(p.Source, binary.BigEndian.Uint16(b[:2]))}
	seq, ack := binary.BigEndian.Uint32(b[4:8]), binary.BigEndian.Uint32(b[8:12])
	flags := b[13]
	wnd := uint32(binary.BigEndian.Uint16(b[14:16]))
	data := b[off:]
	c := s.find(k)
	if c == nil {
		if flags&flagRST != 0 {
			return
		}
		l := s.listener(k.local)
		if l == nil || flags&(flagSYN|flagACK|flagFIN) != flagSYN {
			s.reset(p)
			return
		}
		c, err = s.newTCP(k, SynReceived)
		if err != nil {
			return
		}
		c.listener = l
		c.rcvNxt = seq + 1
		c.rcvAdv = c.rcvNxt + uint32(c.receiveLimit)
		c.peerWindow = wnd
		c.sndWL1 = seq
		c.sndWL2 = c.iss
		if err = c.negotiate(opts); err != nil {
			return
		}
		if err = s.add(c); err != nil {
			return
		}
		c.mu.Lock()
		c.enqueueControl(flagSYN)
		c.pump(time.Now())
		c.mu.Unlock()
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.state == Closed {
		return
	}
	if c.state == SynSent {
		if flags&flagACK != 0 && (ack != c.iss+1 || ack != c.sndNxt) {
			if flags&flagRST == 0 {
				s.reset(p)
			}
			return
		}
		if flags&flagRST != 0 {
			if flags&flagACK != 0 {
				c.finish(errors.New("lightweight: connection refused"))
			}
			return
		}
		if flags&flagSYN == 0 {
			return
		}
		c.rcvNxt = seq + 1
		c.rcvAdv = c.rcvNxt + uint32(c.receiveLimit)
		c.peerWindow = wnd
		if err = c.negotiate(opts); err != nil {
			c.finish(err)
			return
		}
		if flags&flagACK == 0 {
			c.state = SynReceived
			if c.tx.len() > 0 {
				c.transmit(c.tx.values()[0], now, true)
			}
			c.schedule(now)
			return
		}
		c.processAck(ack, wnd, seq, opts, now, true)
		c.state = Established
		c.notifyAll()
		c.sendACK()
		if len(data) > 0 {
			c.receive(seq+1, data, flags&flagFIN != 0, now)
		}
		c.pump(now)
		return
	}
	if c.state == SynReceived && flags&flagSYN != 0 && seq+1 == c.rcvNxt {
		if c.tx.len() > 0 {
			c.transmit(c.tx.values()[0], now, true)
		}
		c.schedule(now)
		return
	}
	if c.state == TimeWait {
		if flags&flagFIN != 0 && seq+uint32(len(data))+1 == c.rcvNxt {
			c.sendACK()
			c.endAt = now.Add(s.config.TimeWait)
			c.schedule(now)
		}
		return
	}
	// RFC 5961: only an exact RCV.NXT reset closes a synchronized connection;
	// an in-window reset gets a challenge ACK, and an out-of-window one is ignored.
	if flags&flagRST != 0 {
		if seq == c.rcvNxt {
			c.finish(fmt.Errorf("lightweight: %w", syscall.ECONNRESET))
		} else if !before(seq, c.rcvNxt) && before(seq, c.rcvAdv) {
			c.sendACK()
		}
		return
	}
	segLen := len(data)
	if flags&flagFIN != 0 {
		segLen++
	}
	acceptable := seq == c.rcvNxt
	if segLen > 0 {
		acceptable = before(seq, c.rcvAdv) && after(seq+uint32(segLen), c.rcvNxt) || len(data) == 0 && flags&flagFIN != 0 && seq == c.rcvNxt
	} else if c.rcvAdv != c.rcvNxt {
		acceptable = !before(seq, c.rcvNxt) && before(seq, c.rcvAdv)
	}
	if !acceptable {
		c.sendACK()
		return
	}
	if flags&flagSYN != 0 {
		c.sendACK()
		return
	}
	if flags&flagACK == 0 {
		return
	}
	if c.state == SynReceived {
		if ack != c.iss+1 || ack != c.sndNxt {
			s.reset(p)
			return
		}
		c.processAck(ack, wnd, seq, opts, now, true)
		c.state = Established
		if c.listener != nil && !c.listener.deliver(c) {
			c.sendReset()
			c.finish(ErrLimit)
			return
		}
		c.notifyAll()
	} else {
		if after(ack, c.sndNxt) {
			c.sendACK()
			return
		}
		c.processAck(ack, wnd, seq, opts, now, len(data) == 0 && flags&flagFIN == 0)
	}
	if c.state == Closed {
		return
	}
	c.lastActive = now
	c.keepaliveSent = 0
	c.persistProbes = 0
	if len(data) > 0 || flags&flagFIN != 0 {
		c.receive(seq, data, flags&flagFIN != 0, now)
	}
	c.pump(now)
}
func (c *TCPConn) negotiate(o tcpOptions) error {
	if o.mss > 0 {
		c.mss = min(c.pathMSS, o.mss)
	}
	if c.mss < 64 {
		return ErrUnsupported
	}
	c.peerScale = o.scale
	c.sack = o.sack
	if c.peerScale < 0 {
		c.ownScale = 0
	}
	cc, err := congestion.New(c.stack.config.CongestionControl, congestion.Config{MSS: uint64(c.mss), MaxWindow: uint64(c.stack.config.SendBuffer)})
	if err != nil {
		return err
	}
	c.controller = cc
	return nil
}
func (s *Stack) reset(p Packet) {
	b := p.Payload
	if b[13]&flagRST != 0 {
		return
	}
	h := int(b[12]>>4) * 4
	reply := make([]byte, 20)
	copy(reply[:2], b[2:4])
	copy(reply[2:4], b[:2])
	reply[12] = 5 << 4
	reply[13] = flagRST
	if b[13]&flagACK != 0 {
		copy(reply[4:8], b[8:12])
	} else {
		n := uint32(len(b) - h)
		if b[13]&flagSYN != 0 {
			n++
		}
		if b[13]&flagFIN != 0 {
			n++
		}
		binary.BigEndian.PutUint32(reply[8:12], binary.BigEndian.Uint32(b[4:8])+n)
		reply[13] |= flagACK
	}
	binary.BigEndian.PutUint16(reply[16:18], transportChecksum(p.Destination, p.Source, 6, reply))
	_ = s.sendIP(p.Destination, p.Source, 6, reply)
}

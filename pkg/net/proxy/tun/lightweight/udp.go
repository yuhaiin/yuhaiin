package lightweight

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// Datagram owns Payload; ReceiveUDP transfers ownership to the caller.
// Forwarding is stateless, so short-lived destinations create no flow entries.
type Datagram struct {
	Source, Destination netip.AddrPort
	Payload             []byte
}
type flowAddress struct{ addr netip.Addr }
type UDPConn struct {
	stack                       *Stack
	local, remote               netip.AddrPort
	mu                          sync.Mutex
	changed                     chan struct{}
	queue                       []Datagram
	bytes                       int
	closed                      bool
	dualStack                   bool
	err                         error
	readDeadline, writeDeadline time.Time
}

var _ net.PacketConn = (*UDPConn)(nil)
var _ net.Conn = (*UDPConn)(nil)

func (s *Stack) ListenUDP(local netip.AddrPort) (*UDPConn, error) {
	return s.DialUDP(local, netip.AddrPort{})
}
func (s *Stack) DialUDP(local, remote netip.AddrPort) (*UDPConn, error) {
	return s.dialUDP(local, remote, false)
}

// ListenDualUDP binds one wildcard socket for both IPv4 and IPv6 datagrams.
// A zero port selects an ephemeral port shared by both families.
func (s *Stack) ListenDualUDP(port uint16) (*UDPConn, error) {
	return s.dialUDP(netip.AddrPortFrom(netip.IPv6Unspecified(), port), netip.AddrPort{}, true)
}

func (s *Stack) dialUDP(local, remote netip.AddrPort, dual bool) (*UDPConn, error) {
	if s.closed() {
		return nil, net.ErrClosed
	}
	if remote.IsValid() && (remote.Port() == 0 || remote.Addr().IsUnspecified() || remote.Addr().IsMulticast()) {
		return nil, ErrMalformed
	}
	if !local.IsValid() {
		var src netip.Addr
		var err error
		if remote.IsValid() {
			src, err = s.source(remote.Addr())
		} else if len(s.config.Addresses) > 0 {
			src = s.config.Addresses[0]
		} else {
			err = errors.New("lightweight: UDP requires a local address")
		}
		if err != nil {
			return nil, err
		}
		local = netip.AddrPortFrom(src, 0)
	}
	if local.Addr().Is4In6() || local.Addr().Zone() != "" || local.Addr().IsMulticast() || !local.Addr().IsUnspecified() && !s.local(local.Addr()) && !s.config.Promiscuous {
		return nil, ErrMalformed
	}
	if remote.IsValid() && local.Addr().Is4() != remote.Addr().Is4() {
		return nil, ErrMalformed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed() {
		return nil, net.ErrClosed
	}
	if len(s.udp) >= s.config.MaxUDPSockets {
		return nil, ErrLimit
	}
	if local.Port() == 0 {
		found := false
		for range 16384 {
			local = netip.AddrPortFrom(local.Addr(), s.port())
			if !s.udpBound(local, dual) {
				found = true
				break
			}
		}
		if !found {
			return nil, ErrLimit
		}
	} else if s.udpBound(local, dual) {
		return nil, errors.New("lightweight: UDP address in use")
	}
	if !s.reserve(1024) {
		return nil, ErrLimit
	}
	u := &UDPConn{stack: s, local: local, remote: remote, dualStack: dual}
	s.udp[local] = u
	return u, nil
}
func (s *Stack) udpBound(a netip.AddrPort, dual bool) bool {
	for k, u := range s.udp {
		if k.Port() == a.Port() && (dual || u.dualStack || k.Addr().Is4() == a.Addr().Is4() && (k.Addr() == a.Addr() || k.Addr().IsUnspecified() || a.Addr().IsUnspecified())) {
			return true
		}
	}
	return false
}
func (s *Stack) handleUDP(p Packet) {
	b := p.Payload
	src := netip.AddrPortFrom(p.Source, binary.BigEndian.Uint16(b[:2]))
	dst := netip.AddrPortFrom(p.Destination, binary.BigEndian.Uint16(b[2:4]))
	s.mu.Lock()
	u := s.udp[dst]
	if u == nil {
		anyAddr := netip.IPv6Unspecified()
		if dst.Addr().Is4() {
			anyAddr = netip.IPv4Unspecified()
		}
		u = s.udp[netip.AddrPortFrom(anyAddr, dst.Port())]
	}
	if u == nil && dst.Addr().Is4() {
		candidate := s.udp[netip.AddrPortFrom(netip.IPv6Unspecified(), dst.Port())]
		if candidate != nil && candidate.dualStack {
			u = candidate
		}
	}
	s.mu.Unlock()
	if u != nil {
		u.deliver(Datagram{src, dst, b[8:]})
		return
	}
	if !s.config.ForwardUDP {
		s.icmpError(p, 3, 3, 0)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed() {
		return
	}
	if !s.reserve(len(b) - 8 + receiveCharge) {
		s.drops.Add(1)
		return
	}
	data := make([]byte, len(b)-8)
	copy(data, b[8:])
	select {
	case s.forwarded <- Datagram{src, dst, data}:
	default:
		s.release(len(data) + receiveCharge)
		s.drops.Add(1)
	}
}
func (u *UDPConn) deliver(d Datagram) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed || u.remote.IsValid() && u.remote != d.Source {
		return
	}
	if len(u.queue) >= 64 || u.bytes+len(d.Payload) > u.stack.config.ReceiveBuffer || !u.stack.reserve(len(d.Payload)+receiveCharge) {
		u.stack.drops.Add(1)
		return
	}
	b := make([]byte, len(d.Payload))
	copy(b, d.Payload)
	d.Payload = b
	u.queue = append(u.queue, d)
	u.bytes += len(b)
	notify(&u.changed)
}
func (s *Stack) ReceiveUDP(ctx context.Context) (Datagram, error) {
	select {
	case <-s.done:
		return Datagram{}, net.ErrClosed
	case <-ctx.Done():
		return Datagram{}, ctx.Err()
	case d := <-s.forwarded:
		s.release(len(d.Payload) + receiveCharge)
		return d, nil
	}
}
func (s *Stack) WriteUDP(src, dst netip.AddrPort, b []byte) (int, error) {
	if s.closed() {
		return 0, net.ErrClosed
	}
	// net.UDPAddr may carry IPv4 addresses as IPv4-mapped IPv6. Generate
	// IPv4 packets for those endpoints rather than rejecting mixed families.
	if src.IsValid() {
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	}
	if dst.IsValid() {
		dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	}
	if !src.IsValid() || !dst.IsValid() || src.Port() == 0 || dst.Port() == 0 || src.Addr().Is4() != dst.Addr().Is4() || src.Addr().IsMulticast() || dst.Addr().IsMulticast() {
		return 0, ErrMalformed
	}
	if src.Addr().IsUnspecified() {
		a, err := s.source(dst.Addr())
		if err != nil {
			return 0, err
		}
		src = netip.AddrPortFrom(a, src.Port())
	}
	maxPayload := 65527
	if src.Addr().Is4() {
		maxPayload = 65507
	}
	if len(b) > maxPayload {
		return 0, ErrMTU
	}
	payload := make([]byte, 8+len(b))
	binary.BigEndian.PutUint16(payload[:2], src.Port())
	binary.BigEndian.PutUint16(payload[2:4], dst.Port())
	binary.BigEndian.PutUint16(payload[4:6], uint16(len(payload)))
	copy(payload[8:], b)
	sum := transportChecksum(src.Addr(), dst.Addr(), 17, payload)
	if sum == 0 {
		sum = 65535
	}
	binary.BigEndian.PutUint16(payload[6:8], sum)
	if err := s.sendDatagram(flowAddress{src.Addr()}, flowAddress{dst.Addr()}, 17, payload); err != nil {
		return 0, err
	}
	return len(b), nil
}
func (u *UDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for {
		if !u.readDeadline.IsZero() && !time.Now().Before(u.readDeadline) {
			return 0, nil, os.ErrDeadlineExceeded
		}
		if u.closed {
			return 0, nil, net.ErrClosed
		}
		if u.err != nil {
			err := u.err
			u.err = nil
			return 0, nil, err
		}
		if len(u.queue) > 0 {
			d := u.queue[0]
			u.queue[0] = Datagram{}
			u.queue = u.queue[1:]
			n := copy(b, d.Payload)
			u.bytes -= len(d.Payload)
			u.stack.release(len(d.Payload) + receiveCharge)
			return n, net.UDPAddrFromAddrPort(d.Source), nil
		}
		ch, at := watch(&u.changed), u.readDeadline
		u.mu.Unlock()
		err := waitSocket(ch, u.stack.done, at)
		u.mu.Lock()
		if err != nil {
			return 0, nil, err
		}
	}
}
func (u *UDPConn) Read(b []byte) (int, error) { n, _, err := u.ReadFrom(b); return n, err }
func (u *UDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	dst, ok := addr.(*net.UDPAddr)
	if !ok || dst == nil || dst.Port < 1 || dst.Port > 65535 || dst.Zone != "" {
		return 0, ErrMalformed
	}
	destination := dst.AddrPort()
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return 0, net.ErrClosed
	}
	if !u.writeDeadline.IsZero() && !time.Now().Before(u.writeDeadline) {
		return 0, os.ErrDeadlineExceeded
	}
	if u.remote.IsValid() && u.remote != destination {
		return 0, errors.New("lightweight: connected UDP destination mismatch")
	}
	source := u.local
	if u.dualStack && destination.Addr().Is4() {
		source = netip.AddrPortFrom(netip.IPv4Unspecified(), source.Port())
	}
	return u.stack.WriteUDP(source, destination, b)
}
func (u *UDPConn) Write(b []byte) (int, error) {
	if !u.remote.IsValid() {
		return 0, errors.New("lightweight: UDP socket is not connected")
	}
	return u.WriteTo(b, net.UDPAddrFromAddrPort(u.remote))
}
func (u *UDPConn) Close() error {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil
	}
	u.closed = true
	for _, d := range u.queue {
		u.stack.release(len(d.Payload) + receiveCharge)
	}
	u.queue = nil
	u.bytes = 0
	notify(&u.changed)
	u.mu.Unlock()
	u.stack.mu.Lock()
	delete(u.stack.udp, u.local)
	u.stack.release(1024)
	u.stack.mu.Unlock()
	return nil
}
func (u *UDPConn) LocalAddr() net.Addr  { return net.UDPAddrFromAddrPort(u.local) }
func (u *UDPConn) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(u.remote) }
func (u *UDPConn) SetDeadline(t time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.readDeadline = t
	u.writeDeadline = t
	notify(&u.changed)
	return nil
}
func (u *UDPConn) SetReadDeadline(t time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.readDeadline = t
	notify(&u.changed)
	return nil
}
func (u *UDPConn) SetWriteDeadline(t time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.writeDeadline = t
	notify(&u.changed)
	return nil
}

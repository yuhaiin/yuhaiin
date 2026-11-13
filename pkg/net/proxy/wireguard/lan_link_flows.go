package wireguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/relay"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

const (
	lanLinkFlowDialTimeout = 10 * time.Second
	lanLinkUDPIdleTimeout  = 2 * time.Minute
)

// lanLinkDialer opens a flow to a destination inside the tunnel subnet.
type lanLinkDialer interface {
	Conn(ctx context.Context, addr netapi.Address) (net.Conn, error)
	PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error)
}

// lanLinkRelay finds the link that owns a tunnel address on the gateway.
// from is the tunnel address of the client that opened the flow; a client is
// never relayed back to itself.
type lanLinkRelay interface {
	relayTarget(from, to netip.Addr) (lanLinkDialer, bool)
}

// lanLinkFlows dispatches the flows that a LAN Link peer sends into this
// side's tunnel stack:
//
//   - destinations in the shared networks go to the inbound handler (gateway
//     only), which applies the usual access and routing policies;
//   - this side's own tunnel address is delivered to the host's loopback
//     address when local is valid;
//   - another client's tunnel address is relayed through that client's link
//     when relay is set (gateway only).
//
// Everything else is dropped.
type lanLinkFlows struct {
	lanLinkFlowSpec

	ctx     context.Context
	mu      sync.Mutex
	packets map[lanLinkPacketKey]*lanLinkPacketSession
}

type lanLinkFlowSpec struct {
	handler netapi.Handler
	routes  []netip.Prefix
	// peer is the tunnel address of the remote side of this link.
	peer netip.Addr
	// local is this side's tunnel address; invalid disables local delivery.
	local  netip.Addr
	subnet netip.Prefix
	relay  lanLinkRelay
}

type lanLinkPacketKey struct{ src, dst netip.AddrPort }

func newLANLinkFlows(ctx context.Context, spec lanLinkFlowSpec) *lanLinkFlows {
	return &lanLinkFlows{lanLinkFlowSpec: spec, ctx: ctx, packets: make(map[lanLinkPacketKey]*lanLinkPacketSession)}
}

// target reports where a flow to addr goes. It returns a nil dialer for the
// shared networks, which are handed to the inbound handler.
func (f *lanLinkFlows) target(addr netapi.Address) (lanLinkDialer, netip.AddrPort, bool) {
	ip, ok := addr.(netapi.IPAddress)
	if !ok {
		return nil, netip.AddrPort{}, false
	}
	dst := ip.AddrPort()
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	if f.handler != nil && slices.ContainsFunc(f.routes, func(p netip.Prefix) bool { return p.Contains(dst.Addr()) }) {
		return nil, dst, true
	}
	if !f.subnet.IsValid() || !f.subnet.Contains(dst.Addr()) {
		return nil, dst, false
	}
	if f.local.IsValid() && dst.Addr() == f.local {
		return loopbackDialer{}, dst, true
	}
	if f.relay != nil {
		if d, ok := f.relay.relayTarget(f.peer, dst.Addr()); ok {
			return d, dst, true
		}
	}
	return nil, dst, false
}

func (f *lanLinkFlows) HandleStream(m *netapi.StreamMeta) {
	d, _, ok := f.target(m.Address)
	if !ok {
		_ = m.Src.Close()
		return
	}
	if d == nil {
		f.handler.HandleStream(m)
		return
	}
	ctx, cancel := context.WithTimeout(f.ctx, lanLinkFlowDialTimeout)
	conn, err := d.Conn(ctx, m.Address)
	cancel()
	if err != nil {
		log.Debug("LAN Link flow", "addr", m.Address, "err", err)
		_ = m.Src.Close()
		return
	}
	relay.RelayContext(f.ctx, m.Src, conn)
}

func (f *lanLinkFlows) HandlePacket(p *netapi.Packet) {
	d, dst, ok := f.target(p.Dst())
	if !ok {
		p.DecRef()
		return
	}
	if d == nil {
		f.handler.HandlePacket(p)
		return
	}
	defer p.DecRef()
	src, ok := p.Src().(*net.UDPAddr)
	if !ok {
		return
	}
	key := lanLinkPacketKey{src: src.AddrPort(), dst: dst}
	f.mu.Lock()
	s := f.packets[key]
	f.mu.Unlock()
	if s == nil {
		ctx, cancel := context.WithTimeout(f.ctx, lanLinkFlowDialTimeout)
		pc, err := d.PacketConn(ctx, p.Dst())
		cancel()
		if err != nil {
			log.Debug("LAN Link packet flow", "addr", p.Dst(), "err", err)
			return
		}
		created := &lanLinkPacketSession{pc: pc, writeBack: p.ReplyWriter(), reply: p.Dst()}
		created.touch()
		f.mu.Lock()
		if s = f.packets[key]; s == nil && f.ctx.Err() == nil {
			s = created
			f.packets[key] = s
			go f.readReplies(key, s)
		}
		f.mu.Unlock()
		if s != created {
			_ = pc.Close()
		}
		if s == nil {
			return
		}
	}
	s.touch()
	_, _ = s.pc.WriteTo(p.GetPayload(), p.Dst())
}

func (f *lanLinkFlows) HandlePing(m *netapi.PingMeta) {
	if f.handler != nil {
		f.handler.HandlePing(m)
	}
}

// Close drops every UDP session.
func (f *lanLinkFlows) Close() {
	f.mu.Lock()
	sessions := f.packets
	f.packets = make(map[lanLinkPacketKey]*lanLinkPacketSession)
	f.mu.Unlock()
	for _, s := range sessions {
		_ = s.pc.Close()
	}
}

func (f *lanLinkFlows) readReplies(key lanLinkPacketKey, s *lanLinkPacketSession) {
	defer func() {
		f.mu.Lock()
		if f.packets[key] == s {
			delete(f.packets, key)
		}
		f.mu.Unlock()
		_ = s.pc.Close()
	}()
	buf := pool.GetBytes(pool.MaxSegmentSize)
	defer pool.PutBytes(buf)
	for {
		_ = s.pc.SetReadDeadline(time.Now().Add(lanLinkUDPIdleTimeout))
		n, _, err := s.pc.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && time.Since(s.lastActive()) < lanLinkUDPIdleTimeout {
				continue
			}
			return
		}
		s.touch()
		if _, err := s.writeBack.WriteBack(buf[:n], s.reply); err != nil && !errors.Is(err, netapi.ErrUndeliverableDatagram) {
			return
		}
	}
}

type lanLinkPacketSession struct {
	pc        net.PacketConn
	writeBack netapi.WriteBack
	reply     netapi.Address
	active    atomic.Int64
}

func (s *lanLinkPacketSession) touch()                { s.active.Store(time.Now().UnixNano()) }
func (s *lanLinkPacketSession) lastActive() time.Time { return time.Unix(0, s.active.Load()) }

// loopbackDialer delivers a flow addressed to this side's own tunnel address to
// the same port on the host's loopback address.
type loopbackDialer struct{}

func loopbackFor(addr netapi.Address) (netip.AddrPort, error) {
	ip, ok := addr.(netapi.IPAddress)
	if !ok {
		return netip.AddrPort{}, errors.New("LAN Link: expected an IP destination")
	}
	loopback := netip.IPv6Loopback()
	if ip.AddrPort().Addr().Unmap().Is4() {
		loopback = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	return netip.AddrPortFrom(loopback, ip.AddrPort().Port()), nil
}

func (loopbackDialer) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	target, err := loopbackFor(addr)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", target.String())
}

func (loopbackDialer) PacketConn(_ context.Context, addr netapi.Address) (net.PacketConn, error) {
	target, err := loopbackFor(addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(target))
	if err != nil {
		return nil, err
	}
	return connectedPacketConn{conn}, nil
}

// connectedPacketConn ignores the destination of writes: the socket is already
// connected to the loopback target.
type connectedPacketConn struct{ *net.UDPConn }

func (c connectedPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return c.UDPConn.Write(b) }

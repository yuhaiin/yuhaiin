package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/peerrendezvous"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweighttun"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func init() {
	register.RegisterContractPoint(transport.PeerTunnelType, func(c transport.PeerTunnel, _ netapi.Proxy) (netapi.Proxy, error) {
		w, _, err := newPeerTunnel(c, peerrendezvous.Dialer)
		if err != nil {
			return nil, err
		}
		if err := w.init(); err != nil {
			_ = w.Close()
			return nil, err
		}
		return &peerDialer{Wireguard: w}, nil
	})
}

func newPeerTunnel(c transport.PeerTunnel, role peerrendezvous.Role) (*Wireguard, []netip.Prefix, error) {
	if err := c.Validate(); err != nil {
		return nil, nil, err
	}
	key, err := transport.DecodePeerKey(c.Token)
	if err != nil {
		return nil, nil, err
	}
	routes, err := ParseEndpoints(c.Routes)
	if err != nil {
		return nil, nil, err
	}
	allowed := c.Routes
	inbound := role == peerrendezvous.Publisher
	if inbound {
		// WireGuard validates all decrypted source IPs against AllowedIPs.
		ip := netip.MustParseAddr(c.PeerIP)
		allowed = []string{netip.PrefixFrom(ip, ip.BitLen()).String()}
	}
	bind := newNetBindClient(nil)
	// The TUN event can open the bind before WireGuard applies its peer
	// configuration. Resolve and seed the underlay endpoint first.
	endpoint, err := bind.ParseEndpoint(c.Coordinator)
	if err != nil {
		return nil, nil, fmt.Errorf("peer tunnel discovery server: %w", err)
	}
	ap := netip.AddrPort(endpoint.(Endpoint))
	coord := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	if ip := coord.Addr(); ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.Zone() != "" {
		return nil, nil, errors.New("peer tunnel discovery server must have a reachable unicast address")
	}
	bind.listenPacket = func(ctx context.Context, _, address string, opts ...func(*dialer.Options)) (net.PacketConn, error) {
		network := "udp4"
		if coord.Addr().Is6() {
			network = "udp6"
		}
		if coord.Addr().IsLoopback() {
			address = net.JoinHostPort(coord.Addr().String(), "0")
		}
		pc, err := dialer.ListenPacket(ctx, network, address, opts...)
		if err != nil {
			return nil, err
		}
		return peerrendezvous.NewSocket(pc, coord, key, role), nil
	}
	w, err := newClient(Config{
		SecretKey: c.PrivateKey,
		Endpoint:  []string{c.LocalIP},
		MTU:       1280,
		Peers: []PeerConfig{{
			PublicKey: c.PeerPublicKey, Endpoint: coord.String(), AllowedIPs: allowed,
		}},
	}, bind, inbound)
	return w, routes, err
}

type peerDialer struct {
	*Wireguard
}

func (p *peerDialer) waitPeer(ctx context.Context) error {
	active := p.bind.active.Load()
	if active == nil {
		return errors.New("peer tunnel: UDP socket unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err := active.conn.(*peerrendezvous.Socket).WaitReady(ctx); err != nil {
		return fmt.Errorf("peer tunnel: waiting for direct UDP path: %w", err)
	}
	return nil
}

func (p *peerDialer) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	if err := p.waitPeer(ctx); err != nil {
		return nil, err
	}
	return p.Wireguard.Conn(ctx, addr)
}

func (p *peerDialer) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	if err := p.waitPeer(ctx); err != nil {
		return nil, err
	}
	return p.Wireguard.PacketConn(ctx, addr)
}

func (*peerDialer) Ping(context.Context, netapi.Address) (uint64, error) {
	return 0, errors.ErrUnsupported
}

type peerPublisher struct {
	*Wireguard
	flows netapi.Accepter
}

func (*peerPublisher) Interface() string { return transport.PeerTunnelType }
func (p *peerPublisher) Close() error    { return errors.Join(p.Wireguard.Close(), p.flows.Close()) }

// NewPeerPublisher starts the LAN-serving peer as part of the inbound lifecycle.
func NewPeerPublisher(c transport.PeerTunnel, handler netapi.Handler) (netapi.Accepter, error) {
	if handler == nil {
		return nil, errors.New("peer tunnel: missing inbound handler")
	}
	w, routes, err := newPeerTunnel(c, peerrendezvous.Publisher)
	if err != nil {
		return nil, err
	}
	flows, err := lightweighttun.NewFromStack(w.net.Stack(), peerRouteFilter{Handler: handler, routes: routes}, nil, transport.PeerTunnelType)
	if err != nil {
		_ = w.Close()
		return nil, err
	}
	p := &peerPublisher{Wireguard: w, flows: flows}
	if err := w.init(); err != nil {
		_ = p.Close()
		return nil, err
	}
	return p, nil
}

type peerRouteFilter struct {
	netapi.Handler
	routes []netip.Prefix
}

func (f peerRouteFilter) allowed(addr netapi.Address) bool {
	ip, ok := addr.(netapi.IPAddress)
	return ok && slices.ContainsFunc(f.routes, func(p netip.Prefix) bool { return p.Contains(ip.AddrPort().Addr()) })
}

func (f peerRouteFilter) HandleStream(m *netapi.StreamMeta) {
	if f.allowed(m.Address) {
		f.Handler.HandleStream(m)
		return
	}
	_ = m.Src.Close()
}

func (f peerRouteFilter) HandlePacket(p *netapi.Packet) {
	if f.allowed(p.Dst()) {
		f.Handler.HandlePacket(p)
		return
	}
	p.DecRef()
}

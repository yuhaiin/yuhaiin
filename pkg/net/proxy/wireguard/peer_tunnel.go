package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	underlay, err := newPeerUnderlay(ctx, c.Coordinator, key, role)
	if err != nil {
		return nil, nil, err
	}
	bind := underlay.bind
	w, err := newClient(Config{
		SecretKey: c.PrivateKey,
		Endpoint:  []string{c.LocalIP},
		MTU:       1280,
		Peers: []PeerConfig{{
			// A placeholder. The rendezvous socket ignores WireGuard's
			// destination and writes to the discovered peer.
			PublicKey: c.PeerPublicKey, Endpoint: underlay.candidates[0].String(), AllowedIPs: allowed,
		}},
	}, bind, inbound)
	if err != nil {
		return nil, nil, err
	}
	underlay.rebind = w.rebind
	return w, routes, nil
}

func newPeerUnderlay(ctx context.Context, address string, key [32]byte, role peerrendezvous.Role) (*peerUnderlay, error) {
	resolve := func(ctx context.Context) ([]netip.AddrPort, error) {
		return peerrendezvous.ResolveCoordinators(ctx, address)
	}
	coordinators, err := resolve(ctx)
	if err != nil {
		return nil, fmt.Errorf("peer tunnel discovery server: %w", err)
	}
	bind := newNetBindClient(nil)
	u := &peerUnderlay{key: key, role: role, bind: bind, candidates: coordinators, resolve: resolve}
	bind.openAddr.Store(net.UDPAddrFromAddrPort(coordinators[0]))
	bind.listenPacket = u.listen
	return u, nil
}

// peerUnderlay picks the discovery server address for each UDP socket. The
// server's hostname can resolve to both IP families, and its address can
// change while a long-lived publisher is running.
type peerUnderlay struct {
	key        [32]byte
	role       peerrendezvous.Role
	bind       *netBindClient
	resolve    func(context.Context) ([]netip.AddrPort, error)
	rebind     func()
	enrollment *peerrendezvous.Enrollment
	exchange   *peerrendezvous.LinkExchange

	mu         sync.Mutex
	candidates []netip.AddrPort // one per IP family, preferred first
	index      int
	current    netip.AddrPort
	requested  bool
}

func (u *peerUnderlay) listen(ctx context.Context, _, address string, opts ...func(*dialer.Options)) (net.PacketConn, error) {
	u.mu.Lock()
	if (!u.requested && u.exchange == nil) || u.index >= len(u.candidates) {
		// A socket opened for a new network path starts again from the
		// preferred address. The previous choice described the old path.
		u.index = 0
	}
	candidates, start := u.candidates, u.index
	u.mu.Unlock()
	var failed error
	// A host without a route for one family cannot open that socket at all.
	for i := range candidates {
		index := (start + i) % len(candidates)
		coord, local := candidates[index], address
		// The hint selects the outgoing interface for this address.
		u.bind.openAddr.Store(net.UDPAddrFromAddrPort(coord))
		network := "udp4"
		if coord.Addr().Is6() {
			network = "udp6"
		}
		if coord.Addr().IsLoopback() {
			local = net.JoinHostPort(coord.Addr().String(), "0")
		}
		ctx, route := netapi.GetOrNewContext(ctx)
		pc, err := dialer.ListenPacket(ctx, network, local, opts...)
		if err != nil {
			failed = errors.Join(failed, err)
			continue
		}
		u.mu.Lock()
		u.index, u.current, u.requested = index, coord, false
		u.mu.Unlock()
		return peerrendezvous.NewManagedSocket(pc, coord, u.key, u.role, func(answered bool, peer netip.Addr) {
			u.refresh(coord, answered, peer)
		}, u.enrollment, u.exchange, localPeerPrefix(pc.LocalAddr(), route.GetInterface(), coord.Addr())), nil
	}
	return nil, failed
}

// Advertise only a private address on the interface selected by the actual
// underlay socket. A wildcard bind borrows its port for that interface address.
func localPeerPrefix(bound net.Addr, interfaceName string, coordinator netip.Addr) netip.Prefix {
	addr, ok := bound.(*net.UDPAddr)
	if !ok || interfaceName == "" || coordinator.IsLoopback() {
		return netip.Prefix{}
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return netip.Prefix{}
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Prefix{}
	}
	ip := addr.AddrPort().Addr().Unmap()
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err == nil && prefix.Addr().IsPrivate() && prefix.Addr().BitLen() == coordinator.BitLen() &&
			(ip.IsUnspecified() || ip == prefix.Addr()) {
			return prefix
		}
	}
	return netip.Prefix{}
}

// refresh handles a socket that cannot serve the pair. It resolves the
// hostname again and replaces the socket when another address should be used.
func (u *peerUnderlay) refresh(coord netip.AddrPort, answered bool, peer netip.Addr) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	candidates, err := u.resolve(ctx)
	if err != nil {
		return
	}
	u.mu.Lock()
	if coord != u.current || u.requested {
		u.mu.Unlock()
		return
	}
	index := min(u.index, len(candidates)-1)
	switch {
	case peer.IsValid():
		// Both sides only move toward the last candidate, so a mixed pair
		// settles on the family they share and cannot swap places.
		if i := slices.IndexFunc(candidates, func(c netip.AddrPort) bool { return c.Addr().BitLen() == peer.BitLen() }); i > index {
			index = i
		}
	case !answered:
		// This host may lack the address family. Try the next one.
		index = (index + 1) % len(candidates)
	}
	replace := candidates[index] != coord
	u.candidates, u.index, u.requested = candidates, index, replace
	u.mu.Unlock()
	if replace {
		u.rebind()
		u.mu.Lock()
		u.requested = false
		u.mu.Unlock()
	}
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

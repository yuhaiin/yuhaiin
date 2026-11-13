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

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/peerrendezvous"
)

func newPeerUnderlay(ctx context.Context, addresses []string, key [32]byte, role peerrendezvous.Role) (*peerUnderlay, error) {
	resolve := func(ctx context.Context) ([]netip.AddrPort, error) {
		return peerrendezvous.ResolveCoordinatorList(ctx, addresses)
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
	key      [32]byte
	role     peerrendezvous.Role
	bind     *netBindClient
	resolve  func(context.Context) ([]netip.AddrPort, error)
	rebind   func()
	exchange *peerrendezvous.LinkExchange
	// open supplies the socket when the coordinator runs in this process.
	open func() (net.PacketConn, netip.AddrPort, error)
	// hosted marks a dialer whose coordinator is the publisher itself.
	hosted bool

	mu         sync.Mutex
	candidates []netip.AddrPort // one per IP family, preferred first
	index      int
	current    netip.AddrPort
	requested  bool
}

func (u *peerUnderlay) listen(ctx context.Context, _, address string, opts ...func(*dialer.Options)) (net.PacketConn, error) {
	if u.open != nil {
		pc, coordinator, err := u.open()
		if err != nil {
			return nil, err
		}
		u.bind.openAddr.Store(net.UDPAddrFromAddrPort(coordinator))
		socket := peerrendezvous.NewManagedSocket(pc, coordinator, u.key, u.role, nil, u.exchange, netip.Prefix{})
		// The in-process coordinator's socket serves both IP families.
		socket.SetDualStack()
		return socket, nil
	}
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
		socket := peerrendezvous.NewManagedSocket(pc, coord, u.key, u.role, func(answered bool, peer netip.Addr) {
			u.refresh(coord, answered, peer)
		}, u.exchange, localPeerPrefix(pc.LocalAddr(), route.GetInterface(), coord.Addr()))
		if u.hosted {
			socket.SetHosted()
		}
		return socket, nil
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

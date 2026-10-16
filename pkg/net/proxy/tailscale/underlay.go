package tailscale

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/netns"
	"tailscale.com/types/nettype"
)

type loopKey struct{}

// Background netstack work does not inherit the context of the user dial.
// Record dependencies between live instances as well as checking the immediate
// context chain, so an already-started A -> B -> A cycle is rejected too.
var underlayGraph = struct {
	sync.Mutex
	edges map[*Tailscale]map[*Tailscale]bool
}{edges: make(map[*Tailscale]map[*Tailscale]bool)}

func checkLoop(ctx context.Context, t *Tailscale) error {
	chain, _ := ctx.Value(loopKey{}).([]*Tailscale)
	if slices.Contains(chain, t) {
		return errors.New("tailscale: recursive underlay proxy chain")
	}
	underlayGraph.Lock()
	defer underlayGraph.Unlock()
	var reaches func(*Tailscale, *Tailscale, map[*Tailscale]bool) bool
	reaches = func(from, target *Tailscale, seen map[*Tailscale]bool) bool {
		if from == target {
			return true
		}
		if seen[from] {
			return false
		}
		seen[from] = true
		for next := range underlayGraph.edges[from] {
			if reaches(next, target, seen) {
				return true
			}
		}
		return false
	}
	for _, owner := range chain {
		if reaches(t, owner, make(map[*Tailscale]bool)) {
			return errors.New("tailscale: recursive underlay proxy chain")
		}
	}
	for _, owner := range chain {
		if underlayGraph.edges[owner] == nil {
			underlayGraph.edges[owner] = make(map[*Tailscale]bool)
		}
		underlayGraph.edges[owner][t] = true
	}
	return nil
}

func forgetUnderlay(t *Tailscale) {
	underlayGraph.Lock()
	defer underlayGraph.Unlock()
	delete(underlayGraph.edges, t)
	for owner, deps := range underlayGraph.edges {
		delete(deps, t)
		if len(deps) == 0 {
			delete(underlayGraph.edges, owner)
		}
	}
}

func appendLoop(ctx context.Context, t *Tailscale) []*Tailscale {
	chain, _ := ctx.Value(loopKey{}).([]*Tailscale)
	return append(slices.Clone(chain), t)
}

type underlay struct {
	owner     *Tailscale
	ancestors []*Tailscale
}

func (u *underlay) network() *netns.Underlay {
	return &netns.Underlay{
		DialContext:    u.dialContext,
		PacketListener: u,
		DNSCache: &dnscache.Resolver{
			Forward: &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return netapi.NewDnsConn(netapi.Bootstrap()), nil
			}},
		},
	}
}

func (u *underlay) context(ctx context.Context) (*netapi.Context, error) {
	// Preserve ancestry across tsnet's own background contexts, so indirect
	// A -> B -> A initialization cycles fail before waiting for either server.
	chain, _ := ctx.Value(loopKey{}).([]*Tailscale)
	chain = slices.Clone(chain)
	for _, ancestor := range u.ancestors {
		if !slices.Contains(chain, ancestor) {
			chain = append(chain, ancestor)
		}
	}
	store := netapi.WithContext(context.WithValue(ctx, loopKey{}, chain))
	store.SetComponent("tailscale")
	// Bootstrap DNS avoids resolving the control/DERP server through this node.
	// The actual connection uses the node's supplied upstream, never ProxyChain.
	store.ConnOptions().SetResolver(*(&netapi.ResolverOptions{}).SetResolver(netapi.Bootstrap()).SetIsResolver())
	return store, u.owner.ctx.Err()
}

// normalizeUnderlayConn enforces the net.Conn contract at the Tailscale
// boundary. A typed-nil *net.TCPConn compares unequal to nil and otherwise
// panics in DERP's asynchronous dial cancellation cleanup.
func normalizeUnderlayConn(ctx context.Context, conn net.Conn, err error) (net.Conn, error) {
	if err != nil {
		if !netapi.IsNilConn(conn) {
			_ = conn.Close()
		}
		return nil, err
	}
	if netapi.IsNilConn(conn) {
		return nil, errors.New("tailscale underlay: upstream returned a nil TCP connection without error")
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func normalizeUnderlayPacketConn(ctx context.Context, pc net.PacketConn, err error) (net.PacketConn, error) {
	if err != nil {
		if !netapi.IsNilPacketConn(pc) {
			_ = pc.Close()
		}
		return nil, err
	}
	if netapi.IsNilPacketConn(pc) {
		return nil, errors.New("tailscale underlay: upstream returned a nil UDP socket without error")
	}
	if err := ctx.Err(); err != nil {
		_ = pc.Close()
		return nil, err
	}
	return pc, nil
}

func (u *underlay) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	addr, err := netapi.ParseAddress(network, address)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, configuration.Timeout)
	defer cancel()
	stop := context.AfterFunc(u.owner.ctx, cancel)
	defer stop()
	store, err := u.context(ctx)
	if err != nil {
		return nil, net.ErrClosed
	}
	// netapi addresses normalize tcp4/tcp6 to tcp. Resolve a constrained
	// infrastructure hostname locally before crossing that interface boundary.
	if network == "tcp4" || network == "tcp6" {
		want4 := network == "tcp4"
		if !addr.IsFqdn() {
			if addr.(netapi.IPAddress).AddrPort().Addr().Is4() != want4 {
				return nil, errors.New("tailscale underlay address family mismatch")
			}
		} else {
			ips, err := netapi.Bootstrap().LookupIP(store, addr.Hostname())
			if err != nil {
				return nil, err
			}
			if ips == nil {
				return nil, errors.New("tailscale underlay DNS returned no addresses")
			}
			candidates := ips.AAAA
			if want4 {
				candidates = ips.A
			}
			var lastErr error
			for _, ip := range candidates {
				if (ip.To4() != nil) != want4 {
					continue
				}
				conn, dialErr := u.owner.dialer.Conn(store, netapi.ParseIPAddr("tcp", ip, addr.Port()))
				conn, dialErr = normalizeUnderlayConn(store, conn, dialErr)
				if dialErr == nil && u.owner.ctx.Err() == nil {
					return conn, nil
				}
				if dialErr == nil {
					_ = conn.Close()
					return nil, net.ErrClosed
				}
				lastErr = dialErr
				if store.Err() != nil {
					return nil, store.Err()
				}
			}
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, errors.New("tailscale underlay DNS has no address in requested family")
		}
	}
	conn, err := u.owner.dialer.Conn(store, addr)
	conn, err = normalizeUnderlayConn(store, conn, err)
	if err != nil {
		return nil, err
	}
	if u.owner.ctx.Err() != nil {
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (u *underlay) ListenPacket(ctx context.Context, network, address string) (nettype.PacketConn, error) {
	if network != "udp4" && network != "udp6" && network != "udp" {
		return nil, fmt.Errorf("tailscale underlay: unsupported network %q", network)
	}
	ctx, cancel := context.WithTimeout(ctx, configuration.Timeout)
	defer cancel()
	stop := context.AfterFunc(u.owner.ctx, cancel)
	defer stop()
	store, err := u.context(ctx)
	if err != nil {
		return nil, net.ErrClosed
	}
	// Preserve UDP family even when a proxy normalizes udp4/udp6 to udp.
	// In particular, separate magicsock IPv4/IPv6 binds must not become two
	// dual-stack sockets competing for the same requested port.
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if host == "" && network != "udp" {
		host = "::"
		if network == "udp4" {
			host = "0.0.0.0"
		}
		address = net.JoinHostPort(host, port)
	}
	store.ConnOptions().SetBindAddress(address)
	var pc net.PacketConn
	if u.owner.dialer == direct.Default {
		// Retain the concrete UDPConn: magicsock can use batching, buffers and GSO.
		pc, err = dialer.ListenPacket(store, network, address)
	} else {
		pc, err = u.owner.dialer.PacketConn(store, packetListenAddress{AddressNetwork: netapi.UDP, network: network})
	}
	pc, err = normalizeUnderlayPacketConn(store, pc, err)
	if err != nil {
		return nil, err
	}
	if u.owner.ctx.Err() != nil {
		_ = pc.Close()
		return nil, net.ErrClosed
	}
	if _, ok := pc.LocalAddr().(*net.UDPAddr); !ok {
		_ = pc.Close()
		return nil, errors.New("tailscale underlay requires a UDP local endpoint")
	}
	if directPC, ok := pc.(*direct.UDPPacketConn); ok {
		// Direct with a selected interface also preserves the native UDP fast path.
		pc = directPC.BufferPacketConn
		if netapi.IsNilPacketConn(pc) {
			return nil, errors.New("tailscale underlay: direct UDP wrapper contains no socket")
		}
	}
	if native, ok := pc.(nettype.PacketConn); ok {
		return native, nil
	}
	return &nettypePacketConn{PacketConn: pc}, nil
}

type nettypePacketConn struct{ net.PacketConn }

func (p *nettypePacketConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	return p.WriteTo(b, net.UDPAddrFromAddrPort(addr))
}
func (p *nettypePacketConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	n, addr, err := p.ReadFrom(b)
	if err != nil {
		return n, netip.AddrPort{}, err
	}
	a, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return n, netip.AddrPort{}, err
	}
	if a.IsFqdn() {
		return n, netip.AddrPort{}, errors.New("tailscale underlay received a non-IP source address")
	}
	return n, a.(netapi.IPAddress).AddrPort(), nil
}

// netapi.DomainAddr normally normalizes udp4/udp6 to udp. Retain the socket
// family at this boundary without changing the public address/config contract.
type packetListenAddress struct {
	netapi.DomainAddr
	network string
}

func (a packetListenAddress) Network() string { return a.network }

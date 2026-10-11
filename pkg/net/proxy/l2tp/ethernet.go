package l2tp

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// The Ethernet endpoint lets the existing gVisor stack own ARP and IPv6
// neighbor discovery, instead of maintaining a second neighbor cache here.
type ethernetNetwork struct {
	ep     *channel.Endpoint
	stack  *stack.Stack
	ctx    context.Context
	cancel context.CancelFunc
	mac    [6]byte
	hasV6  bool
	once   sync.Once
}

func newEthernetNetwork(cfg Config) (*ethernetNetwork, error) {
	n := &ethernetNetwork{}
	_, _ = rand.Read(n.mac[:])
	n.mac[0] = (n.mac[0] | 2) &^ 1
	n.ctx, n.cancel = context.WithCancel(context.Background())
	n.ep = channel.New(256, uint32(cfg.MTU+14), tcpip.LinkAddress(n.mac[:]))
	n.stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6}, HandleLocal: true,
	})
	if err := n.stack.CreateNIC(1, ethernet.New(n.ep)); err != nil {
		_ = n.Close()
		return nil, fmt.Errorf("l2tpv3: NIC: %s", err)
	}
	for _, pair := range []struct{ address, router string }{{cfg.Address, cfg.Router}, {cfg.IPv6Address, cfg.IPv6Router}} {
		if pair.address == "" {
			continue
		}
		prefix, _ := netip.ParsePrefix(pair.address)
		proto := ipv4.ProtocolNumber
		defaultSubnet := header.IPv4EmptySubnet
		if prefix.Addr().Is6() {
			proto = ipv6.ProtocolNumber
			defaultSubnet = header.IPv6EmptySubnet
			n.hasV6 = true
		}
		address := tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(prefix.Addr().AsSlice()), PrefixLen: prefix.Bits()}}
		if err := n.stack.AddProtocolAddress(1, address, stack.AddressProperties{}); err != nil {
			_ = n.Close()
			return nil, fmt.Errorf("l2tpv3: address: %s", err)
		}
		n.stack.AddRoute(tcpip.Route{Destination: address.AddressWithPrefix.Subnet(), NIC: 1})
		var gateway tcpip.Address
		if pair.router != "" {
			ip, _ := netip.ParseAddr(pair.router)
			gateway = tcpip.AddrFromSlice(ip.AsSlice())
		}
		n.stack.AddRoute(tcpip.Route{Destination: defaultSubnet, NIC: 1, Gateway: gateway})
	}
	if n.hasV6 {
		// Link-local source addresses are needed when the configured IPv6 router
		// is link-local. Build a stable interface identifier from this session MAC.
		linkLocal := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, n.mac[0] ^ 2, n.mac[1], n.mac[2], 0xff, 0xfe, n.mac[3], n.mac[4], n.mac[5]}
		addr := tcpip.ProtocolAddress{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom16(linkLocal), PrefixLen: 64}}
		if err := n.stack.AddProtocolAddress(1, addr, stack.AddressProperties{}); err != nil {
			_ = n.Close()
			return nil, fmt.Errorf("l2tpv3: link-local address: %s", err)
		}
	}
	return n, nil
}

func (n *ethernetNetwork) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	if len(packets) == 0 || len(slab) < 2*tun.ReadPacketSpacing {
		return 0, tun.ErrTooManySegments
	}
	p := n.ep.ReadContext(n.ctx)
	if p == nil {
		return 0, net.ErrClosed
	}
	defer p.DecRef()
	view := p.ToView()
	defer view.Release()
	b := slab[tun.ReadPacketSpacing : len(slab)-tun.ReadPacketSpacing]
	if view.Size() > len(b) {
		return 0, tun.ErrTooManySegments
	}
	packets[0] = tun.ReadPacket{Offset: tun.ReadPacketSpacing, Size: copy(b, view.AsSlice())}
	return 1, nil
}
func (n *ethernetNetwork) Write(buffers [][]byte, offset int) (int, error) {
	if err := n.ctx.Err(); err != nil {
		return 0, net.ErrClosed
	}
	for _, b := range buffers {
		if offset < 0 || offset > len(b) {
			return 0, errors.New("l2tpv3: invalid frame offset")
		}
		b = b[offset:]
		if len(b) < 14 {
			continue
		}
		if b[0]&1 == 0 && !bytes.Equal(b[:6], n.mac[:]) {
			continue
		}
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
		n.ep.InjectInbound(0, p)
		p.DecRef()
	}
	return len(buffers), nil
}
func (n *ethernetNetwork) Close() error {
	n.once.Do(func() { n.cancel(); n.stack.RemoveNIC(1); n.stack.Destroy(); n.ep.Close() })
	return nil
}
func fullAddress(addr net.IP, port int) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	proto := ipv6.ProtocolNumber
	if ip := addr.To4(); ip != nil {
		addr = ip
		proto = ipv4.ProtocolNumber
	}
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(addr), Port: uint16(port)}, proto
}
func (n *ethernetNetwork) DialContextTCP(ctx context.Context, addr *net.TCPAddr) (*gonet.TCPConn, error) {
	a, proto := fullAddress(addr.IP, addr.Port)
	return gonet.DialContextTCP(ctx, n.stack, a, proto)
}
func (n *ethernetNetwork) DialUDP(local, remote *net.UDPAddr) (*gonet.UDPConn, error) {
	proto := ipv4.ProtocolNumber
	if n.hasV6 {
		proto = ipv6.ProtocolNumber
	}
	var la, ra *tcpip.FullAddress
	if local != nil {
		a, p := fullAddress(local.IP, local.Port)
		if local.IP.IsUnspecified() {
			a.Addr = tcpip.Address{}
		}
		if local.Port != 0 || len(local.IP) > 0 && !local.IP.IsUnspecified() {
			la = &a
		}
		proto = p
	}
	if remote != nil {
		a, p := fullAddress(remote.IP, remote.Port)
		ra = &a
		proto = p
	}
	return gonet.DialUDP(n.stack, la, ra, proto)
}

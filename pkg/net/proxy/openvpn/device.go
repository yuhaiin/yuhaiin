package openvpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/gvisor"
	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type ChannelDevice struct {
	events chan tun.Event
	mtu    int
	rwc    net.Conn
}

func NewChannelDevice(mtu int, rwc net.Conn) *ChannelDevice {
	if mtu <= 0 {
		mtu = nat.MaxSegmentSize
	}
	ct := &ChannelDevice{
		mtu:    mtu,
		events: make(chan tun.Event, 1),
		rwc:    rwc,
	}

	ct.events <- tun.EventUp
	return ct
}

func (p *ChannelDevice) Read(b [][]byte, size []int, offset int) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	n, err := p.rwc.Read(b[0][offset:])
	if err != nil {
		return 0, err
	}

	size[0] = n

	return 1, nil
}

func (p *ChannelDevice) Write(b [][]byte, offset int) (int, error) {

	for _, bb := range b {
		_, err := p.rwc.Write(bb[offset:])
		if err != nil {
			return 0, err
		}
	}

	return len(b), nil
}

func (p *ChannelDevice) Close() error {
	close(p.events)
	return p.rwc.Close()
}

func (p *ChannelDevice) BatchSize() int           { return 1 }
func (p *ChannelDevice) Name() (string, error)    { return "channelTun", nil }
func (p *ChannelDevice) MTU() (int, error)        { return p.mtu, nil }
func (p *ChannelDevice) File() *os.File           { return nil }
func (p *ChannelDevice) Events() <-chan tun.Event { return p.events }

func CreateNetTUN(mtu int, rw net.Conn) (*stack.Stack, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        true,
	}

	ep := gvisor.NewEndpoint(device.NewDevice(NewChannelDevice(mtu, rw), 0, mtu))
	stack := stack.New(opts)

	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // TCP SACK is disabled by default
	tcpipErr := stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not enable TCP SACK: %v", tcpipErr)
	}

	tcpipErr = stack.CreateNIC(1, ep)
	if tcpipErr != nil {
		return nil, fmt.Errorf("CreateNIC: %v", tcpipErr)
	}

	// for _, ip := range localAddresses {
	// 	var protoNumber tcpip.NetworkProtocolNumber
	// 	if ip.Addr().Is4() {
	// 		protoNumber = ipv4.ProtocolNumber
	// 	} else if ip.Addr().Is6() {
	// 		protoNumber = ipv6.ProtocolNumber
	// 	}

	// 	protoAddr := tcpip.ProtocolAddress{
	// 		AddressWithPrefix: tcpip.AddressWithPrefix{
	// 			Address:   tcpip.AddrFromSlice(ip.Addr().Unmap().AsSlice()),
	// 			PrefixLen: ip.Bits(),
	// 		},
	// 		Protocol: protoNumber,
	// 	}

	// 	tcpipErr := dev.stack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{})
	// 	if tcpipErr != nil {
	// 		dev.Close()
	// 		return nil, fmt.Errorf("AddProtocolAddress(%v): %v", ip, tcpipErr)
	// 	}
	// 	if ip.Addr().Is4() {
	// 		dev.hasV4 = true
	// 	} else if ip.Addr().Is6() {
	// 		dev.hasV6 = true
	// 	}
	// }

	stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})

	opt := tcpip.CongestionControlOption("cubic")
	if tcpipErr = stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); tcpipErr != nil {
		return nil, fmt.Errorf("SetTransportProtocolOption(%d, &%T(%s)): %s", tcp.ProtocolNumber, opt, opt, tcpipErr)
	}

	return stack, nil
}

type dialer struct {
	stack *stack.Stack
}

func NewDialer(stack *stack.Stack) *dialer {
	return &dialer{
		stack: stack,
	}
}

func (n *dialer) toFullAddr(ip net.IP, port int) (*tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	if ip.To4() == nil {
		protoNumber = ipv6.ProtocolNumber
	} else {
		protoNumber = ipv4.ProtocolNumber
		ip = ip.To4()
	}

	return &tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(ip),
		Port: uint16(port),
	}, protoNumber
}

func (net *dialer) DialContextTCP(ctx context.Context, addr *net.TCPAddr) (*gonet.TCPConn, error) {
	if addr == nil {
		return nil, errors.New("addr is nil")
	}

	gonetAddr, protoNumber := net.toFullAddr(addr.IP, addr.Port)

	return gonet.DialContextTCP(ctx, net.stack, *gonetAddr, protoNumber)
}

func (net *dialer) ListenTCP(addr *net.TCPAddr) (*gonet.TCPListener, error) {
	if addr == nil {
		// pn := ipv4.ProtocolNumber
		// if net.HasV6() {
		pn := ipv6.ProtocolNumber
		// }
		return gonet.ListenTCP(net.stack, tcpip.FullAddress{}, pn)
	}

	gonetAddr, protoNumber := net.toFullAddr(addr.IP, addr.Port)
	return gonet.ListenTCP(net.stack, *gonetAddr, protoNumber)
}

func (n *dialer) DialUDP(laddr, raddr *net.UDPAddr) (*gonet.UDPConn, error) {
	var pn tcpip.NetworkProtocolNumber
	var la, ra *tcpip.FullAddress
	if laddr != nil && laddr.Port > 0 {
		la, pn = n.toFullAddr(laddr.IP, laddr.Port)
	}

	if raddr != nil && raddr.Port > 0 {
		ra, pn = n.toFullAddr(raddr.IP, raddr.Port)
	}

	if pn == 0 {
		// if n.HasV6() {
		pn = ipv6.ProtocolNumber
		// } else {
		// pn = ipv4.ProtocolNumber
		// }
	}

	return gonet.DialUDP(n.stack, la, ra, pn)
}

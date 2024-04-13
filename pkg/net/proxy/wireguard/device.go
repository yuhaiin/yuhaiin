package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"

	gun "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/gvisor"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
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

type netTun struct {
	ep           *gun.Endpoint
	stack        *stack.Stack
	events       chan tun.Event
	hasV4, hasV6 bool
	dev          *gun.ChannelTun
}

type Net netTun

func CreateNetTUN(localAddresses []netip.Prefix, mtu int) (tun.Device, *Net, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        true,
	}

	rwc := gun.NewChannelTun(context.TODO(), mtu)
	dev := &netTun{
		ep:     gun.NewEndpoint(gun.NewDevice(rwc, 0), uint32(mtu)),
		dev:    rwc,
		stack:  stack.New(opts),
		events: make(chan tun.Event, 1),
	}

	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // TCP SACK is disabled by default
	tcpipErr := dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	if tcpipErr != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("could not enable TCP SACK: %v", tcpipErr)
	}

	tcpipErr = dev.stack.CreateNIC(1, dev.ep)
	if tcpipErr != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("CreateNIC: %v", tcpipErr)
	}

	for _, ip := range localAddresses {
		var protoNumber tcpip.NetworkProtocolNumber
		if ip.Addr().Is4() {
			protoNumber = ipv4.ProtocolNumber
		} else if ip.Addr().Is6() {
			protoNumber = ipv6.ProtocolNumber
		}

		protoAddr := tcpip.ProtocolAddress{
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(ip.Addr().Unmap().AsSlice()),
				PrefixLen: ip.Bits(),
			},
			Protocol: protoNumber,
		}

		tcpipErr := dev.stack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{})
		if tcpipErr != nil {
			dev.Close()
			return nil, nil, fmt.Errorf("AddProtocolAddress(%v): %v", ip, tcpipErr)
		}
		if ip.Addr().Is4() {
			dev.hasV4 = true
		} else if ip.Addr().Is6() {
			dev.hasV6 = true
		}
	}

	if dev.hasV4 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if dev.hasV6 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}

	opt := tcpip.CongestionControlOption("cubic")
	if tcpipErr = dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); tcpipErr != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("SetTransportProtocolOption(%d, &%T(%s)): %s", tcp.ProtocolNumber, opt, opt, tcpipErr)
	}

	dev.events <- tun.EventUp
	return dev, (*Net)(dev), nil
}

// convert endpoint string to netip.Addr
func parseEndpoints(conf *protocol.Wireguard) ([]netip.Prefix, error) {
	endpoints := make([]netip.Prefix, 0, len(conf.Endpoint))
	for _, str := range conf.Endpoint {
		prefix, err := netip.ParsePrefix(str)
		if err != nil {
			addr, err := netip.ParseAddr(str)
			if err != nil {
				return nil, err
			}

			if addr.Is4() {
				prefix = netip.PrefixFrom(addr, 32)
			} else {
				prefix = netip.PrefixFrom(addr, 128)
			}
		}

		endpoints = append(endpoints, prefix)
	}

	return endpoints, nil
}

func (tun *netTun) Name() (string, error)    { return "go", nil }
func (tun *netTun) File() *os.File           { return nil }
func (tun *netTun) Events() <-chan tun.Event { return tun.events }
func (tun *netTun) BatchSize() int           { return 1 }

func (tun *netTun) Read(buf [][]byte, size []int, offset int) (int, error) {
	var err error
	size[0], err = tun.dev.Inbound(buf[0][offset:])
	if err != nil {
		return 0, err
	}

	return 1, nil

}

func (tun *netTun) Write(buffers [][]byte, offset int) (int, error) {
	n := 0
	for _, buf := range buffers {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}

		err := tun.dev.Outbound(packet)
		if err != nil {
			if n > 0 {
				return n, nil
			}
			return 0, err
		}

		n++
	}

	return n, nil
}

func (tun *netTun) Flush() error { return nil }

func (tun *netTun) Close() error {
	tun.stack.Destroy()

	if tun.events != nil {
		close(tun.events)
	}
	tun.ep.Close()
	tun.dev.Close()
	return nil
}

func (tun *netTun) MTU() (int, error) { return int(tun.ep.MTU()), nil }

func convertToFullAddr(endpoint netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	if endpoint.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else {
		protoNumber = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(endpoint.Addr().Unmap().AsSlice()),
		Port: endpoint.Port(),
	}, protoNumber
}

func (net *Net) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (*gonet.TCPConn, error) {
	fa, pn := convertToFullAddr(addr)
	return gonet.DialContextTCP(ctx, net.stack, fa, pn)
}

func (net *Net) DialContextTCP(ctx context.Context, addr *net.TCPAddr) (*gonet.TCPConn, error) {
	if addr == nil {
		return net.DialContextTCPAddrPort(ctx, netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(ip, uint16(addr.Port)))
}

func (net *Net) DialTCPAddrPort(addr netip.AddrPort) (*gonet.TCPConn, error) {
	fa, pn := convertToFullAddr(addr)
	return gonet.DialTCP(net.stack, fa, pn)
}

func (net *Net) DialTCP(addr *net.TCPAddr) (*gonet.TCPConn, error) {
	if addr == nil {
		return net.DialTCPAddrPort(netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return net.DialTCPAddrPort(netip.AddrPortFrom(ip, uint16(addr.Port)))
}

func (net *Net) ListenTCPAddrPort(addr netip.AddrPort) (*gonet.TCPListener, error) {
	fa, pn := convertToFullAddr(addr)
	return gonet.ListenTCP(net.stack, fa, pn)
}

func (net *Net) ListenTCP(addr *net.TCPAddr) (*gonet.TCPListener, error) {
	if addr == nil {
		return net.ListenTCPAddrPort(netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return net.ListenTCPAddrPort(netip.AddrPortFrom(ip, uint16(addr.Port)))
}

func (net *Net) DialUDPAddrPort(laddr, raddr netip.AddrPort) (*gonet.UDPConn, error) {
	var lfa, rfa *tcpip.FullAddress
	var pn tcpip.NetworkProtocolNumber
	if laddr.IsValid() || laddr.Port() > 0 {
		var addr tcpip.FullAddress
		addr, pn = convertToFullAddr(laddr)
		lfa = &addr
	}
	if raddr.IsValid() || raddr.Port() > 0 {
		var addr tcpip.FullAddress
		addr, pn = convertToFullAddr(raddr)
		rfa = &addr
	}

	if pn == 0 {
		if net.HasV6() {
			pn = ipv6.ProtocolNumber
		} else {
			pn = ipv4.ProtocolNumber
		}
	}

	return gonet.DialUDP(net.stack, lfa, rfa, pn)
}

func (net *Net) ListenUDPAddrPort(laddr netip.AddrPort) (*gonet.UDPConn, error) {
	return net.DialUDPAddrPort(laddr, netip.AddrPort{})
}

func (net *Net) DialUDP(laddr, raddr *net.UDPAddr) (*gonet.UDPConn, error) {
	var la, ra netip.AddrPort
	if laddr != nil {
		ip, _ := netip.AddrFromSlice(laddr.IP)
		la = netip.AddrPortFrom(ip, uint16(laddr.Port))
	}
	if raddr != nil {
		ip, _ := netip.AddrFromSlice(raddr.IP)
		ra = netip.AddrPortFrom(ip, uint16(raddr.Port))
	}
	return net.DialUDPAddrPort(la, ra)
}

func (net *Net) ListenUDP(laddr *net.UDPAddr) (*gonet.UDPConn, error) {
	return net.DialUDP(laddr, nil)
}

func (n *Net) HasV4() bool { return n.hasV4 }
func (n *Net) HasV6() bool { return n.hasV6 }

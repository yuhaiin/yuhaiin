package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

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

type NetTun struct {
	ep           *gvisor.Endpoint
	stack        *stack.Stack
	events       chan tun.Event
	dev          *ChannelDevice
	hasV4, hasV6 bool
}

func CreateNetTUN(localAddresses []netip.Prefix, mtu int) (*NetTun, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        true,
	}

	rwc := NewChannelDevice(context.TODO(), mtu)
	dev := &NetTun{
		ep:     gvisor.NewEndpoint(device.NewDevice(rwc, 0, mtu)),
		dev:    rwc,
		stack:  stack.New(opts),
		events: make(chan tun.Event, 1),
	}

	tcpipErr := dev.stack.CreateNIC(1, dev.ep)
	if tcpipErr != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("CreateNIC: %v", tcpipErr)
	}

	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // TCP SACK is disabled by default
	dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)

	tr := tcpip.TCPRecovery(0)
	dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &tr)

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
			_ = dev.Close()
			return nil, fmt.Errorf("AddProtocolAddress(%v): %v", ip, tcpipErr)
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

	opt := tcpip.CongestionControlOption("reno")
	if tcpipErr = dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); tcpipErr != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("SetTransportProtocolOption(%d, &%T(%s)): %s", tcp.ProtocolNumber, opt, opt, tcpipErr)
	}

	dev.events <- tun.EventUp
	return dev, nil
}

// convert endpoint string to netip.Addr
func ParseEndpoints(addresses []string) ([]netip.Prefix, error) {
	endpoints := make([]netip.Prefix, 0, len(addresses))
	for _, str := range addresses {
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

func (tun *NetTun) Name() (string, error)    { return "go", nil }
func (tun *NetTun) File() *os.File           { return nil }
func (tun *NetTun) Events() <-chan tun.Event { return tun.events }
func (tun *NetTun) BatchSize() int           { return 1 }

func (tun *NetTun) Read(buf [][]byte, size []int, offset int) (int, error) {
	var err error
	size[0], err = tun.dev.Inbound(buf[0][offset:])
	if err != nil {
		return 0, err
	}

	return 1, nil
}

func (tun *NetTun) Write(buffers [][]byte, offset int) (int, error) {
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

func (tun *NetTun) Flush() error { return nil }

func (tun *NetTun) Close() error {
	tun.stack.RemoveNIC(1)
	tun.stack.Destroy()

	if tun.events != nil {
		close(tun.events)
	}
	tun.ep.Close()
	return tun.dev.Close()
}

func (tun *NetTun) MTU() (int, error) { return int(tun.ep.MTU()), nil }

func (n *NetTun) toFullAddr(ip net.IP, port int) (*tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
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

func (net *NetTun) DialContextTCP(ctx context.Context, addr *net.TCPAddr) (*gonet.TCPConn, error) {
	if addr == nil {
		return nil, errors.New("addr is nil")
	}

	gonetAddr, protoNumber := net.toFullAddr(addr.IP, addr.Port)

	return gonet.DialContextTCP(ctx, net.stack, *gonetAddr, protoNumber)
}

func (net *NetTun) ListenTCP(addr *net.TCPAddr) (*gonet.TCPListener, error) {
	if addr == nil {
		pn := ipv4.ProtocolNumber
		if net.HasV6() {
			pn = ipv6.ProtocolNumber
		}
		return gonet.ListenTCP(net.stack, tcpip.FullAddress{}, pn)
	}

	gonetAddr, protoNumber := net.toFullAddr(addr.IP, addr.Port)
	return gonet.ListenTCP(net.stack, *gonetAddr, protoNumber)
}

func (n *NetTun) DialUDP(laddr, raddr *net.UDPAddr) (*gonet.UDPConn, error) {
	var pn tcpip.NetworkProtocolNumber
	var la, ra *tcpip.FullAddress
	if laddr != nil && laddr.Port > 0 {
		la, pn = n.toFullAddr(laddr.IP, laddr.Port)
	}

	if raddr != nil && raddr.Port > 0 {
		ra, pn = n.toFullAddr(raddr.IP, raddr.Port)
	}

	if pn == 0 {
		if n.HasV6() {
			pn = ipv6.ProtocolNumber
		} else {
			pn = ipv4.ProtocolNumber
		}
	}

	return gonet.DialUDP(n.stack, la, ra, pn)
}

func (n *NetTun) HasV4() bool { return n.hasV4 }
func (n *NetTun) HasV6() bool { return n.hasV6 }

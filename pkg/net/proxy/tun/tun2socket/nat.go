package tun2socket

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type Nat struct {
	*TCP
	*UDP
	*Ping

	tab *tableSplit

	postDown func()

	device.InterfaceAddress
	gatewayPort uint16
}

func dualStackListen(v4addr, v6addr netip.Addr) (v4, v6 *net.TCPListener, port int, err error) {
	v4iface, err := getTunInterfaceByAddress(v4addr)
	if err != nil {
		log.Warn("get v4 interface failed", "err", err)
	} else {
		log.Info("bind v4 listener to interface", "iface", v4iface)
	}

	v6iface, err := getTunInterfaceByAddress(v6addr)
	if err != nil {
		log.Warn("get v6 interface failed", "err", err)
	} else {
		log.Info("bind v6 listener to interface", "iface", v6iface)
	}

	var er error
	for range 5 {
		v4listener, err := dialer.ListenContextWithOptions(context.Background(),
			"tcp", net.JoinHostPort(v4addr.String(), "0"), &dialer.Options{
				InterfaceName: v4iface,
			})
		if err != nil {
			log.Warn("dual stack listen v4 failed", "err", err)
			er = errors.Join(er, err)
			continue
		}

		port := v4listener.Addr().(*net.TCPAddr).Port

		v6listener, err := dialer.ListenContextWithOptions(context.Background(),
			"tcp", net.JoinHostPort(v6addr.String(), fmt.Sprint(port)), &dialer.Options{
				InterfaceName: v6iface,
			})
		if err != nil {
			v4listener.Close()
			log.Warn("dual stack listen v6 failed", "err", err)
			er = errors.Join(er, err)
			continue
		}

		return v4listener.(*net.TCPListener), v6listener.(*net.TCPListener), port, nil
	}

	return nil, nil, 0, err
}

func Start(opt *device.Opt) (*Nat, error) {
	var err error
	// set address and route to interface
	// otherwize the listener will not work
	opt.UnsetRoute, err = netlink.Route(opt.Options)
	if err != nil {
		log.Warn("set route failed", "err", err)
	}

	v4listener, v6listener, gatewayPort, err := dualStackListen(opt.V4Address().Addr(), opt.V6Address().Addr())
	if err != nil {
		if opt.UnsetRoute != nil {
			opt.UnsetRoute()
		}
		return nil, err
	}

	log.Info("new tun2socket tcp server",
		"v4 listener", v4listener.Addr(), "v6 listener", v6listener.Addr(),
		"v4 gateway", opt.V4Address(), "v4 portal", opt.V4Address().Addr().Next(),
		"v6 gateway", opt.V6Address(), "v6 portal", opt.V6Address().Addr().Next(),
	)

	opt.PostUp()

	if opt.MTU <= 0 {
		opt.MTU = nat.MaxSegmentSize
	}

	tab := newTable()

	nat := &Nat{
		InterfaceAddress: opt.InterfaceAddress(),
		gatewayPort:      uint16(gatewayPort),
		tab:              tab,
		TCP:              NewTCP(opt, v4listener, v6listener, tab),
		UDP:              NewUDP(opt),
		Ping:             &Ping{opt},
		postDown:         opt.PostDown,
	}

	var broadcast, v4network, v6network tcpip.Address

	if opt.V4Address().Bits() < 32 {
		subnet := tcpip.AddressWithPrefix{Address: nat.InterfaceAddress.Addressv4, PrefixLen: opt.V4Address().Bits()}.Subnet()
		// broadcast address, eg: 172.19.0.255, ipv6 don't have broadcast address
		broadcast = subnet.Broadcast()
		// network address, eg: 172.19.0.0
		v4network = tcpip.AddrFromSlice(opt.V4Address().Masked().Addr().AsSlice())

		if broadcast.Equal(nat.InterfaceAddress.Addressv4) || broadcast.Equal(nat.InterfaceAddress.Portalv4) {
			broadcast = tcpip.AddrFrom4([4]byte{255, 255, 255, 255})
		}
	}

	if opt.V6Address().Bits() < 127 {
		v6network = tcpip.AddrFromSlice(opt.V6Address().Masked().Addr().AsSlice())
	}

	go func() {
		defer tab.Close()
		defer nat.Close()

		offset := opt.Device.Offset()
		sizes := make([]int, opt.Device.Tun().BatchSize())
		bufs := make([][]byte, opt.Device.Tun().BatchSize())
		for i := range bufs {
			bufs[i] = make([]byte, opt.MTU+offset)
		}

		wbufs := make([][]byte, opt.Device.Tun().BatchSize())

		for {
			n, err := opt.Device.Read(bufs, sizes)
			if err != nil {
				if errors.Is(err, syscall.ENOBUFS) {
					log.Warn("tun device read failed", "err", err)
					continue
				}

				log.Error("tun device read failed", "err", err)
				return
			}

			wbufs = wbufs[:0]

			for i := range n {
				if sizes[i] < header.IPv4MinimumSize {
					continue
				}

				raw := bufs[i][offset : sizes[i]+offset]

				ip := nat.processIP(raw)
				if ip == nil {
					continue
				}

				if !configuration.IPv6.Load() {
					_, ok := ip.(header.IPv6)
					if ok {
						continue
					}
				}

				if len(ip.Payload()) > len(raw) {
					continue
				}

				dst, src := ip.DestinationAddress(), ip.SourceAddress()

				if !net.IP(dst.AsSlice()).IsGlobalUnicast() {
					continue
				}

				if v4network.Len() != 0 && (dst.Equal(broadcast) || dst.Equal(v4network)) {
					continue
				}

				if v6network.Len() != 0 && dst.Equal(v6network) {
					continue
				}

				switch ip.TransportProtocol() {
				case header.TCPProtocolNumber:
					tp, pseudoHeaderSum, ok := nat.processTCP(ip, src, dst)
					if !ok {
						continue
					}

					device.ResetChecksum(ip, tp, pseudoHeaderSum)
					wbufs = append(wbufs, bufs[i][:sizes[i]+offset])

				case header.ICMPv4ProtocolNumber:
					nat.Ping.HandlePing4(bufs[i])
					continue

				case header.ICMPv6ProtocolNumber:
					nat.Ping.HandlePing6(bufs[i])
					continue

				case header.UDPProtocolNumber:
					u := header.UDP(ip.Payload())
					if u.Length() == 0 {
						continue
					}

					nat.UDP.handleUDPPacket(UDPTuple{
						SourceAddr:      src,
						SourcePort:      u.SourcePort(),
						DestinationAddr: dst,
						DestinationPort: u.DestinationPort(),
					}, u.Payload())

					continue

				default:
					continue
				}
			}

			if len(wbufs) == 0 {
				continue
			}

			if _, err = opt.Device.Write(wbufs); err != nil {
				log.Error("write tcp raw to tun device failed", "err", err)
			}

		}
	}()

	return nat, nil
}

func (n *Nat) processIP(raw []byte) header.Network {
	switch header.IPVersion(raw) {
	case header.IPv4Version:
		ipv4 := header.IPv4(raw)

		if !ipv4.IsValid(int(ipv4.TotalLength())) {
			return nil
		}

		if ipv4.More() {
			return nil
		}

		if ipv4.FragmentOffset() != 0 {
			return nil
		}

		return ipv4

	case header.IPv6Version:
		ipv6 := header.IPv6(raw)

		if ipv6.HopLimit() == 0x00 {
			return nil
		}

		return ipv6
	}

	return nil
}

func (n *Nat) processTCP(ip header.Network, src, dst tcpip.Address) (_ header.Transport, pseudoHeaderSum uint16, _ bool) {
	t := header.TCP(ip.Payload())

	sourcePort := t.SourcePort()
	destinationPort := t.DestinationPort()

	var address, portal tcpip.Address
	_, ipv4 := ip.(header.IPv4)
	if ipv4 {
		address, portal = n.Addressv4, n.Portalv4
	} else {
		address, portal = n.AddressV6, n.PortalV6
	}

	if address.Unspecified() || portal.Unspecified() {
		return nil, 0, false
	}

	if src == address && sourcePort == n.gatewayPort {
		tup := n.tab.tupleOf(destinationPort, !ipv4)
		if tup == zeroTuple {
			return nil, 0, false
		}

		ip.SetDestinationAddress(tup.SourceAddr)
		t.SetDestinationPort(tup.SourcePort)
		ip.SetSourceAddress(tup.DestinationAddr)
		t.SetSourcePort(tup.DestinationPort)
	} else {
		tup := Tuple{
			SourceAddr:      src,
			SourcePort:      sourcePort,
			DestinationAddr: dst,
			DestinationPort: destinationPort,
		}

		port := n.tab.portOf(tup)
		if port == 0 {
			log.Warn("all port already used", "dst", dst, "dstPort", destinationPort)
			return nil, 0, false
		}
		ip.SetDestinationAddress(address)
		t.SetDestinationPort(n.gatewayPort)
		ip.SetSourceAddress(portal)
		t.SetSourcePort(port)
	}

	pseudoHeaderSum = header.PseudoHeaderChecksum(header.TCPProtocolNumber,
		ip.SourceAddress(),
		ip.DestinationAddress(),
		uint16(len(ip.Payload())),
	)

	return t, pseudoHeaderSum, true
}

func (n *Nat) Close() error {
	var err error

	if n.UDP != nil {
		if er := n.UDP.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	if n.TCP != nil {
		if er := n.TCP.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	if n.postDown != nil {
		n.postDown()
	}

	return err
}

func processICMP(ip header.Network) (_ header.Transport, pseudoHeaderSum uint16, _ bool) {
	i := header.ICMPv4(ip.Payload())

	if i.Type() != header.ICMPv4Echo || i.Code() != 0 {
		return nil, 0, false
	}

	i.SetType(header.ICMPv4EchoReply)

	destination := ip.DestinationAddress()
	ip.SetDestinationAddress(ip.SourceAddress())
	ip.SetSourceAddress(destination)

	pseudoHeaderSum = 0

	return i, pseudoHeaderSum, true
}

func processICMPv6(ip header.Network) (_ header.Transport, pseudoHeaderSum uint16, _ bool) {
	i := header.ICMPv6(ip.Payload())

	if i.Type() != header.ICMPv6EchoRequest || i.Code() != 0 {
		return nil, 0, false
	}

	i.SetType(header.ICMPv6EchoReply)

	destination := ip.DestinationAddress()
	ip.SetDestinationAddress(ip.SourceAddress())
	ip.SetSourceAddress(destination)

	pseudoHeaderSum = header.PseudoHeaderChecksum(header.ICMPv6ProtocolNumber,
		ip.SourceAddress(), ip.DestinationAddress(),
		uint16(len(i)),
	)

	return i, pseudoHeaderSum, true
}

func getTunInterfaceByAddress(addr netip.Addr) (string, error) {
	interfaces, err := interfaces.GetInterfaceList()
	if err != nil {
		return "", err
	}

	ip := addr.AsSlice()

	for _, i := range interfaces {
		addrs, err := i.Addrs()
		if err != nil {
			log.Warn("get interface addr failed", "err", err)
			continue
		}

		for _, a := range addrs {
			v, ok := a.(*net.IPNet)
			if !ok {
				continue
			}

			if v.Contains(ip) {
				return i.Name, nil
			}
		}
	}

	return "", errors.New("not found")
}

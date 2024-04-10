package nat

import (
	"context"
	"errors"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	tun "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/gvisor"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var _ IP = (header.IPv4)(nil)

type IP interface {
	Payload() []byte
	SourceAddress() tcpip.Address
	DestinationAddress() tcpip.Address
	SetSourceAddress(tcpip.Address)
	SetDestinationAddress(tcpip.Address)
	SetChecksum(v uint16)
	PayloadLength() uint16
	TransportProtocol() tcpip.TransportProtocolNumber
}

type TransportProtocol interface {
	SetChecksum(v uint16)
}

type Nat struct {
	*TCP
	*UDP

	address     tcpip.Address
	portal      tcpip.Address
	addressV6   tcpip.Address
	portalV6    tcpip.Address
	gatewayPort uint16
	mtu         int32

	tab *tableSplit
}

func Start(opt *tun.Opt) (*Nat, error) {
	listener, err := dialer.ListenContextWithOptions(context.Background(), "tcp", "", &dialer.Options{})
	if err != nil {
		return nil, err
	}

	log.Info("new tun2socket tcp server", "host", listener.Addr(),
		"gateway", opt.V4Address(), "portal", opt.V4Address().Addr().Next(),
		"gatewayv6", opt.V6Address(), "portalv6", opt.V6Address().Addr().Next(),
	)

	err = netlink.Route(opt.Options)
	if err != nil {
		log.Warn("set route failed", "err", err)
	}

	if opt.MTU <= 0 {
		opt.MTU = nat.MaxSegmentSize
	}

	tab := newTable()

	nat := &Nat{
		address:     tcpip.AddrFromSlice(opt.V4Address().Addr().AsSlice()),
		portal:      tcpip.AddrFromSlice(opt.V4Address().Addr().Next().AsSlice()),
		addressV6:   tcpip.AddrFromSlice(opt.V6Address().Addr().AsSlice()),
		portalV6:    tcpip.AddrFromSlice(opt.V6Address().Addr().Next().AsSlice()),
		gatewayPort: uint16(listener.Addr().(*net.TCPAddr).Port),
		mtu:         int32(opt.MTU),
		tab:         tab,
		TCP: &TCP{
			listener: listener.(*net.TCPListener),
			portal:   opt.V4Address().Addr().Next().AsSlice(),
			portalv6: opt.V6Address().Addr().Next().AsSlice(),
			table:    tab,
		},
		UDP: NewUDPv2(int32(opt.MTU), opt.Writer),
	}

	subnet := tcpip.AddressWithPrefix{Address: nat.address, PrefixLen: opt.V4Address().Bits()}.Subnet()
	broadcast := subnet.Broadcast()
	if broadcast.Equal(nat.address) || broadcast.Equal(nat.portal) {
		broadcast = tcpip.AddrFrom4([4]byte{255, 255, 255, 255})
	}

	go func() {
		defer nat.Close()

		sizes := make([]int, opt.Writer.BatchSize())
		bufs := make([][]byte, opt.Writer.BatchSize())
		for i := range bufs {
			bufs[i] = make([]byte, opt.MTU)
		}

		wbufs := make([][]byte, opt.Writer.BatchSize())

		for {
			n, err := opt.Writer.Read(bufs, sizes)
			if err != nil {
				log.Error("tun device read failed", "err", err)
				return
			}

			wbufs = wbufs[:0]

			for i := range n {
				raw := bufs[i][:sizes[i]]

				ip := nat.processIP(raw)
				if ip == nil {
					continue
				}

				if ip.PayloadLength() > uint16(len(raw)) {
					log.Warn("ip payload length too large", "length", ip.PayloadLength(), "raw length", len(raw))
					continue
				}

				dst, src := ip.DestinationAddress(), ip.SourceAddress()

				if !net.IP(dst.AsSlice()).IsGlobalUnicast() || dst.Equal(broadcast) {
					continue
				}

				var tp TransportProtocol
				var pseudoHeaderSum uint16
				var ok bool

				switch ip.TransportProtocol() {
				case header.TCPProtocolNumber:
					tp, pseudoHeaderSum, ok = nat.processTCP(ip, src, dst)

				case header.ICMPv4ProtocolNumber:
					tp, pseudoHeaderSum, ok = processICMP(ip)

				case header.ICMPv6ProtocolNumber:
					tp, pseudoHeaderSum, ok = processICMPv6(ip)

				case header.UDPProtocolNumber:
					u := header.UDP(ip.Payload())
					nat.UDP.handleUDPPacket(Tuple{
						SourceAddr:      src,
						SourcePort:      u.SourcePort(),
						DestinationAddr: dst,
						DestinationPort: u.DestinationPort(),
					}, u.Payload())

					continue

				default:
					continue
				}

				if !ok {
					continue
				}

				resetCheckSum(ip, tp, pseudoHeaderSum)

				wbufs = append(wbufs, raw)
			}

			if len(wbufs) == 0 {
				continue
			}

			if _, err = opt.Writer.Write(wbufs); err != nil {
				log.Error("write tcp raw to tun device failed", "err", err)
			}

		}
	}()

	return nat, nil
}

func (n *Nat) processIP(raw []byte) IP {
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

func (n *Nat) processTCP(ip IP, src, dst tcpip.Address) (_ TransportProtocol, pseudoHeaderSum uint16, _ bool) {

	t := header.TCP(ip.Payload())

	sourcePort := t.SourcePort()
	destinationPort := t.DestinationPort()

	var address, portal tcpip.Address
	if _, ok := ip.(header.IPv4); ok {
		address, portal = n.address, n.portal
	} else {
		address, portal = n.addressV6, n.portalV6
	}

	if address.Unspecified() || portal.Unspecified() {
		return nil, 0, false
	}

	if dst.Equal(portal) {
		if src == address && sourcePort == n.gatewayPort {
			tup := n.tab.tupleOf(destinationPort, dst.Len() == 16)
			if tup == zeroTuple {
				return nil, 0, false
			}

			ip.SetDestinationAddress(tup.SourceAddr)
			t.SetDestinationPort(tup.SourcePort)
			ip.SetSourceAddress(tup.DestinationAddr)
			t.SetSourcePort(tup.DestinationPort)
		}
	} else {
		tup := Tuple{
			SourceAddr:      src,
			SourcePort:      sourcePort,
			DestinationAddr: dst,
			DestinationPort: destinationPort,
		}

		port := n.tab.portOf(tup)
		// if port == 0 {
		// 	if t.Flags() != header.TCPFlagSyn {
		// 		return nil, 0, false
		// 	}

		// 	port = n.tab.newConn(tup)
		// }

		ip.SetDestinationAddress(address)
		t.SetDestinationPort(n.gatewayPort)
		ip.SetSourceAddress(portal)
		t.SetSourcePort(port)
	}

	pseudoHeaderSum = header.PseudoHeaderChecksum(header.TCPProtocolNumber,
		ip.SourceAddress(),
		ip.DestinationAddress(),
		ip.PayloadLength(),
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

	return err
}

func processICMP(ip IP) (_ TransportProtocol, pseudoHeaderSum uint16, _ bool) {
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

func processICMPv6(ip IP) (_ TransportProtocol, pseudoHeaderSum uint16, _ bool) {
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

func resetCheckSum(ip IP, tp TransportProtocol, pseudoHeaderSum uint16) {
	if ip, ok := ip.(header.IPv4); ok {
		ip.SetChecksum(0)
		ip.SetChecksum(^checksum.Checksum(ip[:ip.HeaderLength()], 0))
	}
	tp.SetChecksum(0)
	tp.SetChecksum(^checksum.Checksum(ip.Payload(), pseudoHeaderSum))
}

package nat

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	tun "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/gvisor"
	wun "golang.zx2c4.com/wireguard/tun"
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
}

type TransportProtocol interface {
	SetChecksum(v uint16)
}

type Nat struct {
	*TCP
	*UDPv2

	portal      tcpip.Address
	gateway     tcpip.Address
	gatewayPort uint16
	portalV6    tcpip.Address
	gatewayV6   tcpip.Address
	mtu         int32

	tab *table
}

func Start(device io.ReadWriter, tc tun.TunScheme, gateway, portal netip.Addr, mtu int32) (*Nat, error) {
	if tun.Preload != nil {
		dev, ok := device.(interface{ Device() wun.Device })
		if ok {
			if err := tun.Preload(tun.Opt{
				Device:  dev.Device(),
				Scheme:  tc,
				Portal:  portal,
				Gateway: gateway,
				Mtu:     mtu,
			}); err != nil {
				log.Warn("preload failed", "err", err)
			}
		}
	}

	listener, err := dialer.ListenContextWithOptions(context.Background(), "tcp", "", &dialer.Options{})
	if err != nil {
		return nil, err
	}

	log.Info("new tun2socket tcp server", "host", listener.Addr())

	if mtu <= 0 {
		mtu = int32(nat.MaxSegmentSize)
	}

	tab := newTable()
	// udp := &UDP{
	// 	device: device,
	// 	mtu:    mtu,
	// }

	// broadcast := net.IP{0, 0, 0, 0}
	// binary.BigEndian.PutUint32(broadcast, binary.BigEndian.Uint32(gateway.To4())|^binary.BigEndian.Uint32(net.IP(network.Mask).To4()))

	nat := &Nat{
		portal:      tcpip.AddrFromSlice(portal.AsSlice()),
		gateway:     tcpip.AddrFromSlice(gateway.AsSlice()),
		gatewayPort: uint16(listener.Addr().(*net.TCPAddr).Port),
		mtu:         mtu,
		tab:         tab,
		TCP: &TCP{
			listener: listener.(*net.TCPListener),
			portal:   gateway.AsSlice(),
			table:    tab,
		},
		UDPv2: NewUDPv2(mtu, device),
	}

	go func() {
		defer nat.Close()

		buf := make([]byte, mtu)

		for {
			n, err := device.Read(buf)
			if err != nil {
				return
			}

			raw := buf[:n]

			var ip IP
			var protocol tcpip.TransportProtocolNumber

			switch header.IPVersion(raw) {
			case header.IPv4Version:
				ipv4 := header.IPv4(raw)

				if !ipv4.IsValid(int(ipv4.TotalLength())) {
					continue
				}

				if ipv4.More() {
					continue
				}

				if ipv4.FragmentOffset() != 0 {
					continue
				}

				protocol = tcpip.TransportProtocolNumber(ipv4.Protocol())

				ip = ipv4

			case header.IPv6Version:
				ipv6 := header.IPv6(raw)

				if ipv6.HopLimit() == 0x00 {
					continue
				}

				protocol = tcpip.TransportProtocolNumber(ipv6.NextHeader())

				ip = ipv6

			default:
				continue
			}

			if ip.PayloadLength() > uint16(len(raw)) {
				log.Warn("payload length too large", "length", ip.PayloadLength(), "raw length", len(raw))
				continue
			}

			dst, src := ip.DestinationAddress(), ip.SourceAddress()

			if !net.IP(dst.AsSlice()).IsGlobalUnicast() {
				continue
			}

			var tp TransportProtocol
			var pseudoHeaderSum uint16
			var ok bool

			switch protocol {
			case header.TCPProtocolNumber:
				tp, pseudoHeaderSum, ok = nat.processTCP(ip, src, dst)
				if !ok {
					continue
				}

			case header.ICMPv4ProtocolNumber:
				tp, pseudoHeaderSum, ok = processICMP(ip)
				if !ok {
					continue
				}

			case header.ICMPv6ProtocolNumber:
				tp, pseudoHeaderSum, ok = processICMPv6(ip)
				if !ok {
					continue
				}

			case header.UDPProtocolNumber:
				u := header.UDP(ip.Payload())
				nat.UDPv2.handleUDPPacket(Tuple{
					SourceAddr:      src,
					SourcePort:      u.SourcePort(),
					DestinationAddr: dst,
					DestinationPort: u.DestinationPort(),
				}, u.Payload())

				continue

			default:
				continue
			}

			resetCheckSum(ip, tp, pseudoHeaderSum)

			if _, err = device.Write(raw); err != nil {
				log.Error("write tcp raw to tun device failed", "err", err)
			}

		}
	}()

	return nat, nil
}

func (n *Nat) processTCP(ip IP, src, dst tcpip.Address) (_ TransportProtocol, pseudoHeaderSum uint16, _ bool) {

	t := header.TCP(ip.Payload())

	sourcePort := t.SourcePort()
	destinationPort := t.DestinationPort()

	var portal, gateway tcpip.Address

	if _, ok := ip.(header.IPv4); ok {
		portal = n.portal
		gateway = n.gateway
	} else {
		portal = n.portalV6
		gateway = n.gatewayV6
	}

	if portal.Unspecified() || gateway.Unspecified() {
		return nil, 0, false
	}

	if src == portal && sourcePort == n.gatewayPort {
		tup := n.tab.tupleOf(destinationPort)
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
			if t.Flags() != header.TCPFlagSyn {
				return nil, 0, false
			}

			port = n.tab.newConn(tup)
		}

		ip.SetDestinationAddress(portal)
		t.SetDestinationPort(n.gatewayPort)
		ip.SetSourceAddress(gateway)
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

	if n.UDPv2 != nil {
		if er := n.UDPv2.Close(); er != nil {
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

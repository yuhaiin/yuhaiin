package nat

import (
	"context"
	"io"
	"net"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
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

func StartGvisor(device io.ReadWriter, gateway, portal netip.Addr, mtu int32) (*TCP, *UDPv2, error) {
	listener, err := dialer.ListenContextWithOptions(context.Background(), "tcp", "", &dialer.Options{})
	if err != nil {
		return nil, nil, err
	}

	tcpipPortal := tcpip.AddrFromSlice(portal.AsSlice())
	tcpipGateway := tcpip.AddrFromSlice(gateway.AsSlice())

	log.Info("new tun2socket tcp server", "host", listener.Addr())

	if mtu <= 0 {
		mtu = int32(nat.MaxSegmentSize)
	}

	tab := newTable()
	// udp := &UDP{
	// 	device: device,
	// 	mtu:    mtu,
	// }

	udp := &UDPv2{
		device:  device,
		mtu:     mtu,
		channel: make(chan *callv2, 80),
	}

	tcp := &TCP{
		listener: listener.(*net.TCPListener),
		portal:   portal.AsSlice(),
		table:    tab,
	}

	// broadcast := net.IP{0, 0, 0, 0}
	// binary.BigEndian.PutUint32(broadcast, binary.BigEndian.Uint32(gateway.To4())|^binary.BigEndian.Uint32(net.IP(network.Mask).To4()))

	gatewayPort := uint16(listener.Addr().(*net.TCPAddr).Port)

	go func() {
		defer func() {
			_ = tcp.Close()
			_ = udp.Close()
		}()

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

			dst, src := ip.DestinationAddress(), ip.SourceAddress()

			if !net.IP(dst.AsSlice()).IsGlobalUnicast() {
				continue
			}

			var tp TransportProtocol
			var pseudoHeaderSum uint16

			switch protocol {
			case header.TCPProtocolNumber:
				t := header.TCP(ip.Payload())

				sourcePort := t.SourcePort()
				destinationPort := t.DestinationPort()

				if dst == tcpipPortal {
					if src != tcpipGateway || sourcePort != gatewayPort {
						continue
					}

					tup := tab.tupleOf(destinationPort)
					if tup == zeroTuple {
						continue
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

					port := tab.portOf(tup)
					if port == 0 {
						if t.Flags() != header.TCPFlagSyn {
							continue
						}

						port = tab.newConn(tup)
					}

					ip.SetDestinationAddress(tcpipGateway)
					t.SetDestinationPort(gatewayPort)
					ip.SetSourceAddress(tcpipPortal)
					t.SetSourcePort(port)
				}

				pseudoHeaderSum = header.PseudoHeaderChecksum(protocol, ip.SourceAddress(), ip.DestinationAddress(), ip.PayloadLength())
				tp = t

			case header.ICMPv4ProtocolNumber:
				i := header.ICMPv4(ip.Payload())

				if i.Type() != header.ICMPv4Echo || i.Code() != 0 {
					continue
				}

				i.SetType(header.ICMPv4EchoReply)

				destination := ip.DestinationAddress()
				ip.SetDestinationAddress(ip.SourceAddress())
				ip.SetSourceAddress(destination)

				pseudoHeaderSum = 0
				tp = i

			case header.ICMPv6ProtocolNumber:
				i := header.ICMPv6(ip.Payload())

				if i.Type() != header.ICMPv6EchoRequest || i.Code() != 0 {
					continue
				}

				i.SetType(header.ICMPv6EchoReply)

				destination := ip.DestinationAddress()
				ip.SetDestinationAddress(ip.SourceAddress())
				ip.SetSourceAddress(destination)

				pseudoHeaderSum = header.PseudoHeaderChecksum(protocol, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(i)))
				tp = i

			case header.UDPProtocolNumber:
				u := header.UDP(ip.Payload())
				udp.handleUDPPacket(Tuple{
					SourceAddr:      src,
					SourcePort:      u.SourcePort(),
					DestinationAddr: dst,
					DestinationPort: u.DestinationPort(),
				}, u.Payload())
				fallthrough

			default:
				continue
			}

			resetCheckSum(ip, tp, pseudoHeaderSum)

			if _, err = device.Write(raw); err != nil {
				log.Error("write tcp raw to tun device failed", "err", err)
			}

		}
	}()

	return tcp, udp, nil
}

func resetCheckSum(ip IP, tp TransportProtocol, pseudoHeaderSum uint16) {
	if ip, ok := ip.(header.IPv4); ok {
		ip.SetChecksum(0)
		ip.SetChecksum(^checksum.Checksum(ip[:ip.HeaderLength()], 0))
	}
	tp.SetChecksum(0)
	tp.SetChecksum(^checksum.Checksum(ip.Payload(), pseudoHeaderSum))
}

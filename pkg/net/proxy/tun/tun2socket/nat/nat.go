package nat

import (
	"io"
	"net"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket/checksum"
	"gvisor.dev/gvisor/pkg/tcpip"
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

type IPv4 interface {
	IP
	HeaderLength() uint8
}

type TransportProtocol interface {
	SetChecksum(v uint16)
}

func StartGvisor(device io.ReadWriter, gateway, portal netip.Addr, mtu int32) (*TCP, *UDP, error) {
	listener, err := net.ListenTCP("tcp", nil)
	if err != nil {
		return nil, nil, err
	}

	log.Infoln("tun2socket gvisor listen at:", listener.Addr())

	if mtu <= 0 {
		mtu = int32(nat.MaxSegmentSize)
	}

	tab := newTable()
	udp := &UDP{
		device: device,
		mtu:    mtu,
	}

	tcp := &TCP{
		listener: listener,
		portal:   portal,
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

				if ipv4.TTL() == 0x00 {
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

			destinationIP, dok := netip.AddrFromSlice([]byte(ip.DestinationAddress()))
			sourceIP, sok := netip.AddrFromSlice([]byte(ip.SourceAddress()))
			if !dok || !sok {
				continue
			}

			if !destinationIP.IsGlobalUnicast() {
				continue
			}

			var tp TransportProtocol
			var pseudoHeaderSum uint32

			switch protocol {
			case header.TCPProtocolNumber:
				t := header.TCP(ip.Payload())

				sourePort := t.SourcePort()
				destinationPort := t.DestinationPort()

				if destinationIP == portal {
					if sourceIP != gateway || sourePort != gatewayPort {
						continue
					}

					tup := tab.tupleOf(destinationPort)
					if tup == zeroTuple {
						continue
					}

					ip.SetDestinationAddress(tcpip.Address(tup.SourceAddr.Addr().AsSlice()))
					t.SetDestinationPort(tup.SourceAddr.Port())
					ip.SetSourceAddress(tcpip.Address(tup.DestinationAddr.Addr().AsSlice()))
					t.SetSourcePort(tup.DestinationAddr.Port())
				} else {
					tup := tuple{
						SourceAddr:      netip.AddrPortFrom(sourceIP, sourePort),
						DestinationAddr: netip.AddrPortFrom(destinationIP, destinationPort),
					}

					port := tab.portOf(tup)
					if port == 0 {
						if t.Flags() != header.TCPFlagSyn {
							continue
						}

						port = tab.newConn(tup)
					}

					ip.SetDestinationAddress(tcpip.Address(gateway.AsSlice()))
					t.SetDestinationPort(gatewayPort)
					ip.SetSourceAddress(tcpip.Address(portal.AsSlice()))
					t.SetSourcePort(port)
				}

				pseudoHeaderSum = PseudoHeaderSum(ip, raw, protocol)
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

				pseudoHeaderSum = PseudoHeaderSum(ip, raw, protocol)
				tp = i

			case header.UDPProtocolNumber:
				u := header.UDP(ip.Payload())
				udp.handleUDPPacket(
					netip.AddrPortFrom(sourceIP, u.SourcePort()),
					netip.AddrPortFrom(destinationIP, u.DestinationPort()),
					u.Payload())
				fallthrough

			default:
				continue
			}

			if ip, ok := ip.(IPv4); ok {
				ip.SetChecksum(0)
				ip.SetChecksum(^checksum.CheckSumCombine(0, raw[:ip.HeaderLength()]))
			}
			tp.SetChecksum(0)
			tp.SetChecksum(^checksum.CheckSumCombine(pseudoHeaderSum, ip.Payload()))

			if _, err = device.Write(raw); err != nil {
				log.Errorln("write tcp raw to tun device failed:", err)
			}

		}
	}()

	return tcp, udp, nil
}

// PseudoHeaderChecksum calculates the pseudo-header checksum for the given
// destination protocol and network address. Pseudo-headers are needed by
// transport layers when calculating their own checksum.
func PseudoHeaderSum(ip IP, ipRaw []byte, protocol tcpip.TransportProtocolNumber) uint32 {
	var sum uint32
	if _, ok := ip.(IPv4); ok {
		sum = checksum.Sum(ipRaw[12:header.IPv4MinimumSize]) // src address + dst address
	} else {
		sum = checksum.Sum(ipRaw[8:header.IPv6FixedHeaderSize]) // src address + dst address
	}
	// Add the length portion of the checksum to the pseudo-checksum.
	payloadLen := ip.PayloadLength()
	sum += checksum.Sum([]byte{byte(payloadLen >> 8), byte(payloadLen)})
	sum += checksum.Sum([]byte{0, byte(protocol)})

	return sum
}

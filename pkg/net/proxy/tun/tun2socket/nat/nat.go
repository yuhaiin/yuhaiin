package nat

import (
	"io"
	"net"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket/tcpip"
)

func Start(device io.ReadWriter, gateway, portal netip.Addr) (*TCP, *UDP, error) {
	if !portal.Is4() || !gateway.Is4() {
		return nil, nil, net.InvalidAddrError("only ipv4 supported")
	}

	listener, err := net.ListenTCP("tcp4", nil)
	if err != nil {
		return nil, nil, err
	}

	tab := newTable()
	udp := &UDP{
		device: device,
		buf:    [65535]byte{},
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

		buf := make([]byte, 65535)

		for {
			n, err := device.Read(buf)
			if err != nil {
				return
			}

			raw := buf[:n]

			if !tcpip.IsIPv4(raw) {
				continue
			}

			ip := tcpip.IPv4Packet(raw)
			if !ip.Valid() {
				continue
			}

			if ip.Flags()&tcpip.FlagMoreFragment != 0 {
				continue
			}

			if ip.FragmentOffset() != 0 {
				continue
			}

			if !ip.DestinationIP().IsGlobalUnicast() {
				continue
			}

			switch ip.Protocol() {
			case tcpip.TCP:
				t := tcpip.TCPPacket(ip.Payload())
				if !t.Valid() {
					continue
				}

				if ip.DestinationIP() == portal {
					if ip.SourceIP() == gateway && t.SourcePort() == gatewayPort {
						tup := tab.tupleOf(t.DestinationPort())
						if tup == zeroTuple {
							continue
						}

						ip.SetSourceIP(tup.DestinationAddr.Addr())
						ip.SetDestinationIP(tup.SourceAddr.Addr())
						t.SetDestinationPort(tup.SourceAddr.Port())
						t.SetSourcePort(tup.DestinationAddr.Port())

						ip.ResetChecksum()
						t.ResetChecksum(ip.PseudoSum())

						_, _ = device.Write(raw)
					}
				} else {
					tup := tuple{
						SourceAddr:      netip.AddrPortFrom(ip.SourceIP(), t.SourcePort()),
						DestinationAddr: netip.AddrPortFrom(ip.DestinationIP(), t.DestinationPort()),
					}

					port := tab.portOf(tup)
					if port == 0 {
						if t.Flags() != tcpip.TCPSyn {
							continue
						}

						port = tab.newConn(tup)
					}

					ip.SetSourceIP(portal)
					ip.SetDestinationIP(gateway)
					t.SetSourcePort(port)
					t.SetDestinationPort(gatewayPort)

					ip.ResetChecksum()
					t.ResetChecksum(ip.PseudoSum())

					if _, err = device.Write(raw); err != nil {
						log.Errorln("write tcp raw to tun device failed:", err)
					}
				}
			case tcpip.UDP:
				u := tcpip.UDPPacket(ip.Payload())
				if !u.Valid() {
					continue
				}

				udp.handleUDPPacket(ip, u)
			case tcpip.ICMP:
				i := tcpip.ICMPPacket(ip.Payload())

				if i.Type() != tcpip.ICMPTypePingRequest || i.Code() != 0 {
					continue
				}

				i.SetType(tcpip.ICMPTypePingResponse)

				source := ip.SourceIP()
				destination := ip.DestinationIP()
				ip.SetSourceIP(destination)
				ip.SetDestinationIP(source)

				ip.ResetChecksum()
				i.ResetChecksum()

				_, _ = device.Write(raw)
			}
		}
	}()

	return tcp, udp, nil
}

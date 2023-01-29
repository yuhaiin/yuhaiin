//go:build tun2socket_origin
// +build tun2socket_origin

package nat

import (
	"io"
	"math/rand"
	"net"
	"net/netip"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket/tcpip"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	gtcpip "gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Start(device io.ReadWriter, gateway, portal netip.Addr, mtu int32) (*TCP, *UDPv2, error) {
	if !portal.Is4() || !gateway.Is4() {
		return nil, nil, net.InvalidAddrError("only ipv4 supported")
	}

	listener, err := net.ListenTCP("tcp", nil)
	if err != nil {
		return nil, nil, err
	}

	log.Infoln("tun2socket listen at:", listener.Addr())

	if mtu <= 0 {
		mtu = int32(nat.MaxSegmentSize)
	}

	tab := newTable()
	udp := &UDPv2{
		device:  device,
		mtu:     mtu,
		channel: make(chan *callv2, 80),
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

			destinationIP := ip.DestinationIP()
			sourceIP := ip.SourceIP()

			if !destinationIP.IsGlobalUnicast() {
				continue
			}

			switch ip.Protocol() {
			case tcpip.TCP:
				t := tcpip.TCPPacket(ip.Payload())
				if !t.Valid() {
					continue
				}

				destinationPort := t.DestinationPort()
				sourcePort := t.SourcePort()

				if destinationIP == portal {
					if sourceIP != gateway || sourcePort != gatewayPort {
						continue
					}

					tup := tab.tupleOf(destinationPort)
					if tup == zeroTuple {
						continue
					}

					ip.SetSourceIP(tup.DestinationAddr.Addr())
					ip.SetDestinationIP(tup.SourceAddr.Addr())
					t.SetDestinationPort(tup.SourceAddr.Port())
					t.SetSourcePort(tup.DestinationAddr.Port())

					ip.DecTimeToLive()
				} else {
					tup := tuple{
						SourceAddr:      netip.AddrPortFrom(sourceIP, sourcePort),
						DestinationAddr: netip.AddrPortFrom(destinationIP, destinationPort),
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
				}

				ip.ResetChecksum()
				t.ResetChecksum(ip.PseudoSum())

				if _, err = device.Write(raw); err != nil {
					log.Errorln("write tcp raw to tun device failed:", err)
				}
			case tcpip.UDP:
				u := tcpip.UDPPacket(ip.Payload())
				if !u.Valid() {
					continue
				}

				udp.handleUDPPacket(
					netip.AddrPortFrom(sourceIP, u.SourcePort()),
					netip.AddrPortFrom(destinationIP, u.DestinationPort()),
					u.Payload())
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
			case tcpip.ICMPv6:
				i := tcpip.ICMPv6Packet(ip.Payload())

				if i.Type() != tcpip.ICMPv6EchoRequest || i.Code() != tcpip.ICMPv6NetworkUnreachable {
					continue
				}

				i.SetType(tcpip.ICMPv6EchoReply)

				ip.SetDestinationIP(ip.SourceIP())
				ip.SetSourceIP(ip.DestinationIP())

				ip.ResetChecksum()
				i.ResetChecksum(ip.PseudoSum())

				_, _ = device.Write(raw)
			}
		}
	}()

	return tcp, udp, nil
}

func (u *UDP) WriteToTCPIP(buf []byte, local, remote netip.AddrPort) (int, error) {
	if u.closed {
		return 0, net.ErrClosed
	}

	ipBuf := pool.GetBytes(u.mtu)
	defer pool.PutBytes(ipBuf)

	if len(buf) > 0xffff {
		return 0, net.InvalidAddrError("invalid ip version")
	}

	if !local.Addr().Is4() || !remote.Addr().Is4() {
		return 0, net.InvalidAddrError("invalid ip version")
	}

	tcpip.SetIPv4(ipBuf)

	ip := tcpip.IPv4Packet(ipBuf)
	ip.SetHeaderLen(tcpip.IPv4HeaderSize)
	ip.SetTotalLength(tcpip.IPv4HeaderSize + tcpip.UDPHeaderSize + uint16(len(buf)))
	ip.SetTypeOfService(0)
	ip.SetIdentification(uint16(rand.Uint32()))
	ip.SetFragmentOffset(0)
	ip.SetTimeToLive(64)
	ip.SetProtocol(tcpip.UDP)
	ip.SetSourceIP(local.Addr())
	ip.SetDestinationIP(remote.Addr())

	udp := tcpip.UDPPacket(ip.Payload())
	udp.SetLength(tcpip.UDPHeaderSize + uint16(len(buf)))
	udp.SetSourcePort(local.Port())
	udp.SetDestinationPort(remote.Port())
	copy(udp.Payload(), buf)

	ip.ResetChecksum()
	udp.ResetChecksum(ip.PseudoSum())

	return u.device.Write(ipBuf[:ip.TotalLen()])
}

// UDP

type call struct {
	cond        *sync.Cond
	buf         []byte
	n           int
	source      netip.AddrPort
	destination netip.AddrPort
}

type UDP struct {
	closed    bool
	mtu       int32
	device    io.Writer
	queueLock sync.Mutex
	queue     []*call
}

func (u *UDP) ReadFrom(buf []byte) (int, netip.AddrPort, netip.AddrPort, error) {
	u.queueLock.Lock()
	defer u.queueLock.Unlock()

	for !u.closed {
		c := &call{
			cond:        sync.NewCond(&u.queueLock),
			buf:         buf,
			n:           -1,
			source:      netip.AddrPort{},
			destination: netip.AddrPort{},
		}

		u.queue = append(u.queue, c)

		c.cond.Wait()

		if c.n >= 0 {
			return c.n, c.source, c.destination, nil
		}
	}

	return -1, netip.AddrPort{}, netip.AddrPort{}, net.ErrClosed
}

func (u *UDP) WriteTo(buf []byte, local, remote netip.AddrPort) (int, error) {
	if u.closed {
		return 0, net.ErrClosed
	}

	ipBuf := pool.GetBytes(u.mtu)
	defer pool.PutBytes(ipBuf)

	if len(buf) > 0xffff {
		return 0, net.InvalidAddrError("invalid ip version")
	}

	if !local.Addr().IsValid() || !remote.Addr().IsValid() {
		return 0, net.InvalidAddrError("invalid src or dst address")
	}

	udpTotalLength := header.UDPMinimumSize + uint16(len(buf))
	var ip IP
	var totalLength uint16
	if remote.Addr().Unmap().Is4() {
		if totalLength = header.IPv4MinimumSize + udpTotalLength; int(u.mtu) < int(totalLength) {
			return 0, net.InvalidAddrError("ip packet total length large than mtu")
		}

		ipv4 := header.IPv4(ipBuf)
		ipv4.Encode(&header.IPv4Fields{
			TOS:            0,
			ID:             uint16(rand.Uint32()),
			TotalLength:    totalLength,
			FragmentOffset: 0,
			TTL:            64,
			Protocol:       uint8(header.UDPProtocolNumber),
			SrcAddr:        gtcpip.Address(local.Addr().AsSlice()),
			DstAddr:        gtcpip.Address(remote.Addr().AsSlice()),
		})

		ip = ipv4
	} else {
		if totalLength = header.IPv6MinimumSize + udpTotalLength; int(u.mtu) < int(totalLength) {
			return 0, net.InvalidAddrError("ip packet total length large than mtu")
		}

		ipv6 := header.IPv6(ipBuf)
		ipv6.Encode(&header.IPv6Fields{
			TransportProtocol: header.UDPProtocolNumber,
			PayloadLength:     udpTotalLength,
			SrcAddr:           gtcpip.Address(local.Addr().AsSlice()),
			DstAddr:           gtcpip.Address(remote.Addr().AsSlice()),
		})

		ip = ipv6
	}

	udp := header.UDP(ip.Payload())
	udp.Encode(&header.UDPFields{
		SrcPort: local.Port(),
		DstPort: remote.Port(),
		Length:  udpTotalLength,
	})
	copy(udp.Payload(), buf)

	resetCheckSum(ip, udp, PseudoHeaderSum(ip, ipBuf, header.UDPProtocolNumber))

	return u.device.Write(ipBuf[:totalLength])
}

func (u *UDP) Close() error {
	u.queueLock.Lock()
	defer u.queueLock.Unlock()

	u.closed = true

	for _, c := range u.queue {
		c.cond.Signal()
	}

	return nil
}

func (u *UDP) handleUDPPacket(source, destination netip.AddrPort, payload []byte) {
	var c *call

	u.queueLock.Lock()

	if len(u.queue) > 0 { // maybe lose packet
		idx := len(u.queue) - 1
		c = u.queue[idx]
		u.queue = u.queue[:idx]
	}

	u.queueLock.Unlock()

	if c != nil {
		c.source = source
		c.destination = destination
		c.n = copy(c.buf, payload)
		c.cond.Signal()
	}
}

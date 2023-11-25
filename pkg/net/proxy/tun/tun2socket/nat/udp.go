package nat

import (
	"io"
	"math/rand"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type callv2 struct {
	buf   []byte
	n     int
	tuple Tuple
}
type UDPv2 struct {
	closed  bool
	mtu     int32
	device  io.Writer
	queueMu sync.Mutex

	channel chan *callv2
}

func (u *UDPv2) ReadFrom(buf []byte) (int, Tuple, error) {
	c, ok := <-u.channel
	if !ok {
		return -1, Tuple{}, net.ErrClosed
	}

	defer pool.PutBytes(c.buf)

	return copy(buf, c.buf[:c.n]), c.tuple, nil
}

func (u *UDPv2) Close() error {
	u.queueMu.Lock()
	defer u.queueMu.Unlock()

	if !u.closed {
		u.closed = true
		close(u.channel)
	}

	return nil
}

func (u *UDPv2) handleUDPPacket(tuple Tuple, payload []byte) {
	u.queueMu.Lock()
	defer u.queueMu.Unlock()

	if u.closed {
		return
	}

	buf := pool.GetBytes(u.mtu)

	u.channel <- &callv2{
		n:     copy(buf, payload),
		buf:   buf,
		tuple: tuple,
	}
}

func (u *UDPv2) WriteTo(buf []byte, tuple Tuple) (int, error) {
	if u.closed {
		return 0, net.ErrClosed
	}

	ipBuf := pool.GetBytes(u.mtu)
	defer pool.PutBytes(ipBuf)

	if len(buf) > 0xffff {
		return 0, net.InvalidAddrError("invalid ip version")
	}

	udpTotalLength := header.UDPMinimumSize + uint16(len(buf))
	var ip IP
	var totalLength uint16
	if tuple.SourceAddr.Len() == 4 {
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
			SrcAddr:        tuple.DestinationAddr,
			DstAddr:        tuple.SourceAddr,
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
			SrcAddr:           tuple.DestinationAddr,
			DstAddr:           tuple.SourceAddr,
		})

		ip = ipv6
	}

	udp := header.UDP(ip.Payload())
	udp.Encode(&header.UDPFields{
		SrcPort: tuple.DestinationPort,
		DstPort: tuple.SourcePort,
		Length:  udpTotalLength,
	})
	copy(udp.Payload(), buf)

	pseudoSum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), ip.PayloadLength())
	resetCheckSum(ip, udp /*PseudoHeaderSum(ip, ipBuf, header.UDPProtocolNumber)*/, pseudoSum)
	return u.device.Write(ipBuf[:totalLength])
}

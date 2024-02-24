package nat

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type callv2 struct {
	buf   *pool.Bytes
	tuple Tuple
}
type UDPv2 struct {
	mtu     int32
	device  io.Writer
	ctx     context.Context
	cancel  context.CancelFunc
	channel chan *callv2
}

func NewUDPv2(mtu int32, device io.Writer) *UDPv2 {
	ctx, cancel := context.WithCancel(context.Background())
	return &UDPv2{
		mtu:     mtu,
		device:  device,
		ctx:     ctx,
		cancel:  cancel,
		channel: make(chan *callv2, 250),
	}
}

func (u *UDPv2) ReadFrom(buf []byte) (int, Tuple, error) {
	select {
	case <-u.ctx.Done():
		return 0, Tuple{}, net.ErrClosed
	case c := <-u.channel:
		defer pool.PutBytesBuffer(c.buf)

		return copy(buf, c.buf.Bytes()), c.tuple, nil
	}
}

func (u *UDPv2) Close() error {
	u.cancel()
	return nil
}

func (u *UDPv2) handleUDPPacket(tuple Tuple, payload []byte) {
	select {
	case u.channel <- &callv2{pool.GetBytesBuffer(u.mtu).Copy(payload), tuple}:
	case <-u.ctx.Done():
	}
}

func (u *UDPv2) WriteTo(buf []byte, tuple Tuple) (int, error) {
	select {
	case <-u.ctx.Done():
		return 0, net.ErrClosed
	default:
	}

	ipBuf := pool.GetBytes(u.mtu)
	defer pool.PutBytes(ipBuf)

	if len(buf) > 0xffff { // ip packet max length
		return 0, fmt.Errorf("udp packet too large: %d", len(buf))
	}

	udpTotalLength := header.UDPMinimumSize + uint16(len(buf))
	var ip IP
	var totalLength uint16
	if tuple.SourceAddr.Len() == 4 {
		if totalLength = header.IPv4MinimumSize + udpTotalLength; int(u.mtu) < int(totalLength) {
			return 0, fmt.Errorf("ip packet total length large than mtu")
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
			return 0, fmt.Errorf("ip packet total length large than mtu")
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

	pseudoSum := header.PseudoHeaderChecksum(header.UDPProtocolNumber,
		ip.SourceAddress(), ip.DestinationAddress(), ip.PayloadLength())
	resetCheckSum(ip, udp, pseudoSum)
	return u.device.Write(ipBuf[:totalLength])
}

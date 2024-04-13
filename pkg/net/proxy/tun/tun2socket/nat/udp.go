package nat

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	i4 "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	i6 "gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

type call struct {
	buf   *pool.Bytes
	tuple Tuple
}
type UDP struct {
	mtu     int32
	device  netlink.Tun
	ctx     context.Context
	cancel  context.CancelFunc
	channel chan *call
}

func NewUDPv2(mtu int32, device netlink.Tun) *UDP {
	ctx, cancel := context.WithCancel(context.Background())
	return &UDP{
		mtu:     mtu,
		device:  device,
		ctx:     ctx,
		cancel:  cancel,
		channel: make(chan *call, 250),
	}
}

func (u *UDP) ReadFrom(buf []byte) (int, Tuple, error) {
	select {
	case <-u.ctx.Done():
		return 0, Tuple{}, net.ErrClosed
	case c := <-u.channel:
		defer c.buf.Free()

		return copy(buf, c.buf.Bytes()), c.tuple, nil
	}
}

func (u *UDP) Close() error {
	u.cancel()
	return nil
}

func (u *UDP) handleUDPPacket(tuple Tuple, payload []byte) {
	select {
	case u.channel <- &call{pool.GetBytesBuffer(u.mtu).Copy(payload), tuple}:
	case <-u.ctx.Done():
	}
}

func (u *UDP) WriteTo(buf []byte, tuple Tuple) (int, error) {
	select {
	case <-u.ctx.Done():
		return 0, net.ErrClosed
	default:
	}

	udpTotalLength := int(header.UDPMinimumSize) + len(buf)

	if udpTotalLength > math.MaxUint16 || udpTotalLength > int(u.mtu) { // ip packet max length
		return 0, fmt.Errorf("udp packet too large: %d", len(buf))
	}

	ipBuf := pool.GetBytes(u.mtu)
	defer pool.PutBytes(ipBuf)

	var ip header.Network
	var totalLength uint16

	if tuple.SourceAddr.Len() == 4 {
		if tuple.DestinationAddr.To4().Unspecified() {
			return 0, fmt.Errorf("send IPv6 packet to IPv4 connection")
		}

		// no ipv4 options set, so ipv4 header size is IPv4MinimumSize
		totalLength = header.IPv4MinimumSize + uint16(udpTotalLength)

		ipv4 := header.IPv4(ipBuf)
		ipv4.Encode(&header.IPv4Fields{
			TOS:            0,
			ID:             uint16(rand.Uint32()),
			TotalLength:    totalLength,
			FragmentOffset: 0,
			TTL:            i4.DefaultTTL,
			Protocol:       uint8(header.UDPProtocolNumber),
			SrcAddr:        tuple.DestinationAddr,
			DstAddr:        tuple.SourceAddr,
		})

		ip = ipv4
	} else {
		// ipv6 header size is fixed
		totalLength = header.IPv6FixedHeaderSize + uint16(udpTotalLength)

		ipv6 := header.IPv6(ipBuf)
		ipv6.Encode(&header.IPv6Fields{
			TransportProtocol: header.UDPProtocolNumber,
			PayloadLength:     uint16(udpTotalLength),
			SrcAddr:           tuple.DestinationAddr,
			DstAddr:           tuple.SourceAddr,
			HopLimit:          i6.DefaultTTL,
			TrafficClass:      0,
		})

		ip = ipv6
	}

	udp := header.UDP(ip.Payload())

	udp.Encode(&header.UDPFields{
		SrcPort: tuple.DestinationPort,
		DstPort: tuple.SourcePort,
		Length:  uint16(udpTotalLength),
	})
	copy(udp.Payload(), buf)

	resetIPCheckSum(ip)

	// On IPv4, UDP checksum is optional, and a zero value indicates the
	// transmitter skipped the checksum generation (RFC768).
	// On IPv6, UDP checksum is not optional (RFC2460 Section 8.1).
	if _, ok := ip.(header.IPv6); ok {
		pseudoSum := header.PseudoHeaderChecksum(header.UDPProtocolNumber,
			ip.SourceAddress(), ip.DestinationAddress(), uint16(len(ip.Payload())))
		resetTransportCheckSum(ip, udp, pseudoSum)
	}

	_, err := u.device.Write([][]byte{ipBuf[:totalLength]})
	if err != nil {
		return 0, err
	}

	return len(buf), nil
}

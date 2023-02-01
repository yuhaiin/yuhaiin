package nat

import (
	"io"
	"math/rand"
	"net"
	"net/netip"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type callv2 struct {
	buf         []byte
	n           int
	source      netip.AddrPort
	destination netip.AddrPort
}
type UDPv2 struct {
	closed    bool
	mtu       int32
	device    io.Writer
	queueLock sync.Mutex

	channel chan *callv2
}

func (u *UDPv2) ReadFrom(buf []byte) (int, netip.AddrPort, netip.AddrPort, error) {
	c, ok := <-u.channel
	if !ok {
		return -1, netip.AddrPort{}, netip.AddrPort{}, net.ErrClosed
	}

	defer pool.PutBytes(c.buf)

	return copy(buf, c.buf[:c.n]), c.source, c.destination, nil
}

func (u *UDPv2) Close() error {
	u.queueLock.Lock()
	defer u.queueLock.Unlock()

	if !u.closed {
		u.closed = true
		close(u.channel)
	}

	return nil
}

func (u *UDPv2) handleUDPPacket(source, destination netip.AddrPort, payload []byte) {
	u.queueLock.Lock()
	defer u.queueLock.Unlock()

	if u.closed {
		return
	}

	buf := pool.GetBytes(u.mtu)

	u.channel <- &callv2{
		n:           copy(buf, payload),
		buf:         buf,
		source:      source,
		destination: destination,
	}
}

func (u *UDPv2) WriteTo(buf []byte, local, remote netip.AddrPort) (int, error) {
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
			SrcAddr:        tcpip.Address(local.Addr().AsSlice()),
			DstAddr:        tcpip.Address(remote.Addr().AsSlice()),
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
			SrcAddr:           tcpip.Address(local.Addr().AsSlice()),
			DstAddr:           tcpip.Address(remote.Addr().AsSlice()),
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

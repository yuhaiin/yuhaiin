package tun2socket

import (
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	i4 "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	i6 "gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

type UDPTuple struct {
	SourceAddr      tcpip.Address
	DestinationAddr tcpip.Address
	SourcePort      uint16
	DestinationPort uint16
}

type UDP struct {
	device  netlink.Tun
	handler netapi.Handler
	closed  atomic.Bool
	device.InterfaceAddress
}

func NewUDP(opt *device.Opt) *UDP {
	return &UDP{device: opt.Device, handler: opt.Handler, InterfaceAddress: opt.InterfaceAddress()}
}

func (u *UDP) Close() error {
	u.closed.Store(true)
	return nil
}

func (u *UDP) handleUDPPacket(tuple UDPTuple, payload []byte) {
	if u.closed.Load() {
		return
	}

	u.handler.HandlePacket(netapi.NewPacket(
		netapi.ParseIPAddr("udp", tuple.SourceAddr.AsSlice(), tuple.SourcePort),
		netapi.ParseIPAddr("udp", tuple.DestinationAddr.AsSlice(), tuple.DestinationPort),
		pool.Clone(payload),
		&UDPWriteBack{u, tuple},
		netapi.WithDNSRequest(u.IsDNSRequest(tuple.DestinationPort, tuple.DestinationAddr)),
	))
}

func (u *UDP) WriteTo(buf []byte, tuple UDPTuple) (int, error) {
	if u.closed.Load() {
		return 0, net.ErrClosed
	}

	tunBuf, err := u.processUDPPacket(buf, tuple)
	if err != nil {
		return 0, err
	}
	defer pool.PutBytes(tunBuf)

	_, err = u.device.Write([][]byte{tunBuf})
	return len(buf), err
}

type Batch struct {
	Payload []byte
	Tuple   UDPTuple
}

// func (u *UDP) WriteBatch(batch []Batch) error {
// 	if u.closed {
// 		return net.ErrClosed
// 	}

// 	buffs := make([][]byte, 0, len(batch))

// 	for _, b := range batch {
// 		tunBuf, err := u.processUDPPacket(b.Payload, b.Tuple)
// 		if err != nil {
// 			log.Error("process udp packet failed:", "err", err)
// 			continue
// 		}
// 		defer pool.PutBytes(tunBuf)

// 		buffs = append(buffs, tunBuf)
// 	}

// 	if len(buffs) == 0 {
// 		return nil
// 	}

// 	_, err := u.device.Write(buffs)
// 	return err
// }

func (u *UDP) processUDPPacket(buf []byte, tuple UDPTuple) ([]byte, error) {
	udpTotalLength := header.UDPMinimumSize + len(buf)

	if udpTotalLength > math.MaxUint16 || udpTotalLength > u.device.MTU() { // ip packet max length
		return nil, fmt.Errorf("udp packet too large: %d", len(buf))
	}

	tunBuf := pool.GetBytes(u.device.MTU() + u.device.Offset())

	ipBuf := tunBuf[u.device.Offset():]

	var ip header.Network
	var totalLength uint16

	dst4Unspecified := tuple.DestinationAddr.To4().Unspecified()

	if tuple.SourceAddr.Len() == 4 && !dst4Unspecified {
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

	device.ResetIPChecksum(ip)

	// On IPv4, UDP checksum is optional, and a zero value indicates the
	// transmitter skipped the checksum generation (RFC768).
	// On IPv6, UDP checksum is not optional (RFC2460 Section 8.1).
	if _, ok := ip.(header.IPv6); ok {
		pseudoSum := header.PseudoHeaderChecksum(header.UDPProtocolNumber,
			ip.SourceAddress(), ip.DestinationAddress(), uint16(len(ip.Payload())))
		device.ResetTransportChecksum(ip, udp, pseudoSum)
	}

	return tunBuf[:totalLength+uint16(u.device.Offset())], nil
}

type UDPWriteBack struct {
	udp   *UDP
	tuple UDPTuple
}

func (h *UDPWriteBack) toTuple(addr net.Addr) (UDPTuple, error) {
	address, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return UDPTuple{}, err
	}

	if address.IsFqdn() {
		return UDPTuple{}, fmt.Errorf("address: %s is not ip address", address.Hostname())
	}

	var daddr net.IP = address.(netapi.IPAddress).AddrPort().Addr().AsSlice()

	if h.tuple.SourceAddr.Len() == 16 {
		daddr = daddr.To16()
	}

	return UDPTuple{
		DestinationAddr: tcpip.AddrFromSlice(daddr),
		DestinationPort: address.Port(),
		SourceAddr:      h.tuple.SourceAddr,
		SourcePort:      h.tuple.SourcePort,
	}, nil
}

func (h *UDPWriteBack) WriteBack(b []byte, addr net.Addr) (int, error) {
	tuple, err := h.toTuple(addr)
	if err != nil {
		return 0, err
	}

	return h.udp.WriteTo(b, tuple)
}

// func (h *WriteBack) WriteBatch(bufs ...netapi.WriteBatchBuf) error {
// 	batch := make([]Batch, 0, len(bufs))

// 	for _, buf := range bufs {
// 		tuple, err := h.toTuple(buf.Addr)
// 		if err != nil {
// 			log.Error("parse addr failed:", "err", err)
// 			continue
// 		}

// 		batch = append(batch, Batch{
// 			Payload: buf.Payload,
// 			Tuple:   tuple,
// 		})
// 	}

// 	return h.nat.UDP.WriteBatch(batch)
// }

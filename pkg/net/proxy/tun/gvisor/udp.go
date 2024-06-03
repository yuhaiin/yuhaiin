package tun

import (
	"context"
	"fmt"
	"math"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// func (t *tunServer) udpForwarder() *udp.Forwarder {
// 	return udp.NewForwarder(t.stack, func(fr *udp.ForwarderRequest) {
// 		var wq waiter.Queue
// 		ep, err := fr.CreateEndpoint(&wq)
// 		if err != nil {
// 			log.Error("create endpoint failed:", "err", err)
// 			return
// 		}

// 		local := gonet.NewUDPConn(&wq, ep)

// 		go func(local *gonet.UDPConn, id stack.TransportEndpointID) {
// 			defer local.Close()

// 			addr, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
// 			if !ok {
// 				return
// 			}

// 			dst := netapi.ParseAddrPort(statistic.Type_udp, netip.AddrPortFrom(addr, id.LocalPort))

// 			for {
// 				buf := pool.GetBytesBuffer(t.mtu)

// 				_ = local.SetReadDeadline(time.Now().Add(nat.IdleTimeout))
// 				_, src, err := buf.ReadFromPacket(local)
// 				if err != nil {
// 					if ne, ok := err.(net.Error); (ok && ne.Timeout()) || err == io.EOF {
// 						return /* ignore I/O timeout & EOF */
// 					}

// 					log.Error("read udp failed:", "err", err)
// 					return
// 				}

// 				err = t.SendPacket(&netapi.Packet{
// 					Src:     src,
// 					Dst:     dst,
// 					Payload: buf,
// 					WriteBack: func(b []byte, addr net.Addr) (int, error) {
// 						from, err := netapi.ParseSysAddr(addr)
// 						if err != nil {
// 							return 0, err
// 						}

// 						// Symmetric NAT
// 						// gVisor udp.NewForwarder only support Symmetric NAT,
// 						// can't set source in udp header
// 						// TODO: rewrite HandlePacket() to support full cone NAT
// 						if from.String() != dst.String() {
// 							return 0, nil
// 						}

// 						n, err := local.WriteTo(b, src)
// 						if err != nil {
// 							return n, err
// 						}

// 						_ = local.SetReadDeadline(time.Now().Add(nat.IdleTimeout))
// 						return n, nil
// 					},
// 				})
// 				if err != nil {
// 					return
// 				}
// 			}

// 		}(local, fr.ID())
// 	})
// }

func (f *tunServer) HandleUDPPacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	srcPort, dstPort := id.RemotePort, id.LocalPort

	length := pkt.Data().Size()
	buf := pool.NewBufferSize(length)
	defer buf.Reset()

	_, err := pkt.Data().ReadTo(buf, true)
	if err != nil {
		return true
	}

	dst := netapi.ParseIPAddrPort(statistic.Type_udp, id.LocalAddress.AsSlice(), int(dstPort))

	_ = f.SendPacket(&netapi.Packet{
		Src:     netapi.ParseIPAddrPort(statistic.Type_udp, id.RemoteAddress.AsSlice(), int(srcPort)),
		Dst:     dst,
		Payload: buf.Bytes(),
		WriteBack: func(b []byte, addr net.Addr) (int, error) {
			return f.WriteUDPBack(b, id.RemoteAddress, srcPort, addr)
		},
	})
	return true
}

func (w *tunServer) WriteUDPBack(data []byte, sourceAddr tcpip.Address, sourcePort uint16, destination net.Addr) (int, error) {
	daddr, err := netapi.ParseSysAddr(destination)
	if err != nil {
		return 0, err
	}

	if daddr.IsFqdn() {
		return 0, fmt.Errorf("send FQDN packet")
	}

	dip := daddr.AddrPort(context.TODO()).V

	if sourceAddr.Len() == 4 && dip.Addr().Is6() {
		return 0, fmt.Errorf("send IPv6 packet to IPv4 connection")
	}

	var addr tcpip.Address
	var sourceNetwork tcpip.NetworkProtocolNumber
	if sourceAddr.Len() == 16 {
		addr = tcpip.AddrFrom16(dip.Addr().As16())
		sourceNetwork = header.IPv6ProtocolNumber
	} else {
		addr = tcpip.AddrFrom4(dip.Addr().As4())
		sourceNetwork = header.IPv4ProtocolNumber
	}

	route, gerr := w.stack.FindRoute(w.nicID, addr, sourceAddr, sourceNetwork, false)
	if gerr != nil {
		return 0, fmt.Errorf("failed to find route: %v", gerr)
	}
	defer route.Release()

	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.UDPMinimumSize + int(route.MaxHeaderLength()),
		Payload:            buffer.MakeWithData(data),
	})
	defer packet.DecRef()

	packet.TransportProtocolNumber = header.UDPProtocolNumber
	udp := header.UDP(packet.TransportHeader().Push(header.UDPMinimumSize))
	pLen := uint16(packet.Size())
	udp.Encode(&header.UDPFields{
		SrcPort: dip.Port(),
		DstPort: sourcePort,
		Length:  pLen,
	})

	// Set the checksum field unless TX checksum offload is enabled.
	// On IPv4, UDP checksum is optional, and a zero value indicates the
	// transmitter skipped the checksum generation (RFC768).
	// On IPv6, UDP checksum is not optional (RFC2460 Section 8.1).
	if route.RequiresTXTransportChecksum() && sourceNetwork == header.IPv6ProtocolNumber {
		xsum := udp.CalculateChecksum(checksum.Combine(
			route.PseudoHeaderChecksum(header.UDPProtocolNumber, pLen),
			packet.Data().Checksum(),
		))
		if xsum != math.MaxUint16 {
			xsum = ^xsum
		}
		udp.SetChecksum(xsum)
	}

	gerr = route.WritePacket(stack.NetworkHeaderParams{
		Protocol: header.UDPProtocolNumber,
		TTL:      route.DefaultTTL(),
		TOS:      0,
	}, packet)
	if gerr != nil {
		route.Stats().UDP.PacketSendErrors.Increment()
		return 0, fmt.Errorf("failed to write packet: %v", gerr)
	}

	route.Stats().UDP.PacketsSent.Increment()
	return len(data), nil
}

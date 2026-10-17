package gvisor

import (
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func (f *tunServer) HandleUDP(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	srcPort, dstPort := id.RemotePort, id.LocalPort

	data := pkt.Data()

	buf := pool.NewWriter(data.Size())

	_, err := data.ReadTo(buf, true)
	if err != nil {
		return true
	}

	// Capture only the revocable writer, not the server and its device. NAT
	// sessions can outlive an inbound replacement or a switch of packet stacks.
	writer := f.udpReply
	f.handler.HandlePacket(netapi.NewPacket(
		netapi.ParseIPAddr("udp", id.RemoteAddress.AsSlice(), srcPort),
		netapi.ParseIPAddr("udp", id.LocalAddress.AsSlice(), dstPort),
		buf.Bytes,
		netapi.WriteBackFunc(func(b []byte, addr net.Addr) (int, error) {
			return writer.write(b, id.RemoteAddress, srcPort, addr)
		}),
		netapi.WithDNSRequest(f.IsDNSRequest(dstPort, id.LocalAddress)),
	))

	return true
}

type udpReply struct {
	stack atomic.Pointer[stack.Stack]
	nicID tcpip.NICID
	mtu   int
}

func newUDPReply(s *stack.Stack, nicID tcpip.NICID, mtu int) *udpReply {
	w := &udpReply{nicID: nicID, mtu: mtu}
	w.stack.Store(s)
	return w
}

func (w *tunServer) WriteUDPBack(data []byte, sourceAddr tcpip.Address, sourcePort uint16, from net.Addr) (int, error) {
	return w.udpReply.write(data, sourceAddr, sourcePort, from)
}

func (w *udpReply) close() {
	w.stack.Store(nil)
}

func (w *udpReply) write(data []byte, sourceAddr tcpip.Address, sourcePort uint16, from net.Addr) (int, error) {
	// Do not hold a shutdown lock across device I/O. Closing the endpoint
	// must be able to interrupt a reply already blocked in WriteRawPacket.
	s := w.stack.Load()
	if s == nil {
		return 0, net.ErrClosed
	}
	tuple, err := tun2socket.ToTuple(sourceAddr, sourcePort, from)
	if err != nil {
		return 0, err
	}

	if sourceAddr.Len() == 4 && tuple.DestinationAddr.Len() == 16 {
		log.Warn("send IPv6 packet to IPv4 connection",
			slog.String("src", sourceAddr.String()),
			slog.String("dst", from.String()),
		)
	}

	var sourceNetwork tcpip.NetworkProtocolNumber
	if sourceAddr.Len() == 16 || tuple.DestinationAddr.Len() == 16 {
		sourceNetwork = header.IPv6ProtocolNumber
	} else {
		sourceNetwork = header.IPv4ProtocolNumber
	}

	buf, err := tun2socket.GenerateUDPPacket(w.mtu, 0, data, tuple)
	if err != nil {
		return 0, err
	}

	gerr := s.WriteRawPacket(w.nicID, sourceNetwork, buffer.MakeWithData(buf))
	if gerr != nil {
		if w.stack.Load() == nil {
			return 0, net.ErrClosed
		}
		return 0, fmt.Errorf("failed to write packet: %v", gerr)
	}

	return len(data), nil
}

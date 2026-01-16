package gvisor

import (
	"fmt"
	"log/slog"
	"net"

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

	f.handler.HandlePacket(netapi.NewPacket(
		netapi.ParseIPAddr("udp", id.RemoteAddress.AsSlice(), srcPort),
		netapi.ParseIPAddr("udp", id.LocalAddress.AsSlice(), dstPort),
		buf.Bytes,
		netapi.WriteBackFunc(func(b []byte, addr net.Addr) (int, error) {
			return f.WriteUDPBack(b, id.RemoteAddress, srcPort, addr)
		}),
		netapi.WithDNSRequest(f.IsDNSRequest(dstPort, id.LocalAddress)),
	))

	return true
}

func (w *tunServer) WriteUDPBack(data []byte, sourceAddr tcpip.Address, sourcePort uint16, from net.Addr) (int, error) {
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

	buf, err := tun2socket.GenerateUDPPacket(int(w.ep.MTU()), 0, data, tuple)
	if err != nil {
		return 0, err
	}

	gerr := w.stack.WriteRawPacket(w.nicID, sourceNetwork, buffer.MakeWithData(buf))
	if gerr != nil {
		return 0, fmt.Errorf("failed to write packet: %v", gerr)
	}

	return len(data), nil
}

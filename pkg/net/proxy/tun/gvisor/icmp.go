package gvisor

import (
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func (f *tunServer) HandleICMPv4(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	ipHdr := header.IPv4(pkt.NetworkHeader().Slice())
	h := header.ICMPv4(pkt.TransportHeader().Slice())

	if h.Type() != header.ICMPv4Echo {
		return false
	}

	if len(h) < header.ICMPv4MinimumSize {
		return true
	}

	localAddressBroadcast := pkt.NetworkPacketInfo.LocalAddressBroadcast

	// As per RFC 1122 section 3.2.1.3, when a host sends any datagram, the IP
	// source address MUST be one of its own IP addresses (but not a broadcast
	// or multicast address).
	localAddr := ipHdr.DestinationAddress()
	if localAddressBroadcast || header.IsV4MulticastAddress(localAddr) {
		localAddr = tcpip.Address{}
	}

	r, err := f.stack.FindRoute(f.nicID, localAddr, ipHdr.SourceAddress(), ipv4.ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		// If we cannot find a route to the destination, silently drop the packet.
		return true
	}
	defer r.Release()

	var newOptions header.IPv4Options

	// DeliverTransportPacket may modify pkt so don't use it beyond
	// this point. Make a deep copy of the data before pkt gets sent as we will
	// be modifying fields. Both the ICMP header (with its type modified to
	// EchoReply) and payload are reused in the reply packet.
	//
	// TODO(gvisor.dev/issue/4399): The copy may not be needed if there are no
	// waiting endpoints. Consider moving responsibility for doing the copy to
	// DeliverTransportPacket so that is is only done when needed.
	replyData := stack.PayloadSince(pkt.TransportHeader())
	defer replyData.Release()

	replyHeaderLength := uint8(header.IPv4MinimumSize + len(newOptions))
	replyIPHdrView := buffer.NewView(int(replyHeaderLength))
	replyIPHdrView.Write(ipHdr[:header.IPv4MinimumSize])
	replyIPHdrView.Write(newOptions)
	replyIPHdr := header.IPv4(replyIPHdrView.AsSlice())
	replyIPHdr.SetHeaderLength(replyHeaderLength)
	replyIPHdr.SetSourceAddress(r.LocalAddress())
	replyIPHdr.SetDestinationAddress(r.RemoteAddress())
	replyIPHdr.SetTTL(r.DefaultTTL())
	replyIPHdr.SetTotalLength(uint16(len(replyIPHdr) + len(replyData.AsSlice())))
	replyIPHdr.SetChecksum(0)
	replyIPHdr.SetChecksum(^replyIPHdr.CalculateChecksum())

	replyICMPHdr := header.ICMPv4(replyData.AsSlice())
	replyICMPHdr.SetType(header.ICMPv4EchoReply)
	replyICMPHdr.SetChecksum(0)
	replyICMPHdr.SetChecksum(^checksum.Checksum(replyData.AsSlice(), 0))

	replyBuf := buffer.MakeWithView(replyIPHdrView)
	replyBuf.Append(replyData.Clone())
	replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()),
		Payload:            replyBuf,
	})
	defer replyPkt.DecRef()

	r.WritePacket(stack.NetworkHeaderParams{
		Protocol: header.ICMPv4ProtocolNumber,
		TTL:      r.DefaultTTL(),
		TOS:      0,
	}, replyPkt)

	return true
}

func (f *tunServer) HandleICMPv6(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	// TODO which current not support set default icmp handler
	return false
}

package gvisor

import (
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestXxx(t *testing.T) {

	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.UDPMinimumSize + int(60),
		Payload:            buffer.MakeWithData([]byte("aaaaaaaaaaaaaaaa")),
	})
	defer packet.DecRef()

	packet.TransportProtocolNumber = header.UDPProtocolNumber
	udp := header.UDP(packet.TransportHeader().Push(header.UDPMinimumSize))
	pLen := uint16(packet.Size())
	udp.Encode(&header.UDPFields{
		SrcPort: 1080,
		DstPort: 1080,
		Length:  pLen,
	})

	t.Log(packet.NetworkHeader().Slice())
	t.Log(packet.TransportHeader().Slice())
	t.Log(packet.Data().AsRange().ToSlice())
}

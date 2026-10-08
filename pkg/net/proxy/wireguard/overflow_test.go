package wireguard

import (
	"bytes"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/gvisor"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type overflowDispatcher struct{ packets chan []byte }

func (d *overflowDispatcher) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, p *stack.PacketBuffer) {
	d.packets <- p.Data().AsRange().ToSlice()
}

func (*overflowDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func TestOversizedPacketKeepsVirtualTUNAlive(t *testing.T) {
	const mtu = 1280
	channel := NewChannelDevice(t.Context(), mtu)
	endpoint := gvisor.NewEndpoint(device.NewDevice(channel, 0, mtu, false))
	t.Cleanup(endpoint.Close)
	dispatcher := &overflowDispatcher{packets: make(chan []byte, 1)}
	endpoint.Attach(dispatcher)

	if err := channel.Outbound(make([]byte, mtu+1)); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize)
	header.IPv4(packet).Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)), Protocol: uint8(header.ICMPv4ProtocolNumber), TTL: 64,
		SrcAddr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), DstAddr: tcpip.AddrFrom4([4]byte{192, 0, 2, 2}),
	})
	if err := channel.Outbound(packet); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-dispatcher.packets:
		if !bytes.Equal(got, packet) {
			t.Fatal("packet after oversized datagram was corrupted")
		}
	case <-channel.ctx.Done():
		t.Fatal("oversized packet closed the virtual TUN")
	case <-time.After(time.Second):
		t.Fatal("virtual TUN stopped forwarding after oversized packet")
	}
}

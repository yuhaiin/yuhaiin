package wireguard

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/tun"
)

var (
	_ tun.Device = (*ChannelDevice)(nil)
	_ tun.Device = (*NetTun)(nil)
)

func TestVirtualDeviceReadSlab(t *testing.T) {
	for _, inbound := range []bool{false, true} {
		t.Run(map[bool]string{false: "channel", true: "nettun"}[inbound], func(t *testing.T) {
			d := NewChannelDevice(context.Background(), 1500)
			defer d.Close()
			payload := []byte("virtual device packet")
			var reader tun.Reader = d
			if inbound {
				reader = &NetTun{dev: d}
				if _, err := d.Write([][]byte{payload}, 0); err != nil {
					t.Fatal(err)
				}
			} else if err := d.Outbound(payload); err != nil {
				t.Fatal(err)
			}
			slab := bytes.Repeat([]byte{0xaa}, len(payload)+2*tun.ReadPacketSpacing)
			packets := make([]tun.ReadPacket, 1)
			n, err := reader.Read(slab, packets)
			if err != nil || n != 1 {
				t.Fatalf("Read() = %d, %v", n, err)
			}
			p := packets[0]
			if p.Offset != tun.ReadPacketSpacing || !bytes.Equal(slab[p.Offset:p.Offset+p.Size], payload) {
				t.Fatalf("packet=%+v slab=%x", p, slab)
			}
			if !bytes.Equal(slab[:p.Offset], bytes.Repeat([]byte{0xaa}, tun.ReadPacketSpacing)) ||
				!bytes.Equal(slab[p.Offset+p.Size:], bytes.Repeat([]byte{0xaa}, tun.ReadPacketSpacing)) {
				t.Fatal("reserved space overwritten")
			}
			if _, err := reader.Read(slab[:tun.ReadPacketSpacing], packets); !errors.Is(err, tun.ErrTooManySegments) {
				t.Fatalf("short slab: %v", err)
			}
		})
	}
}

type receiveTestConn struct {
	net.PacketConn
	payload []byte
	addr    *net.UDPAddr
}

func (c *receiveTestConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return copy(b, c.payload), c.addr, nil
}

func TestReceiveSlab(t *testing.T) {
	pc := &receiveTestConn{payload: []byte{1, 2, 3, 4, 5, 6}, addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51820}}
	b := &netBindClient{conn: pc}
	slab := make([]byte, 1500)
	packets := make([]conn.ReceivedPacket, 1)
	n, err := b.receive(slab, packets)
	if err != nil || n != 1 {
		t.Fatalf("receive() = %d, %v", n, err)
	}
	packet := packets[0]
	if !bytes.Equal(packet.Bytes(slab), []byte{1, 0, 0, 0, 5, 6}) || packet.Endpoint != Endpoint(pc.addr.AddrPort()) {
		t.Fatalf("packet=%+v payload=%x", packet, packet.Bytes(slab))
	}
}

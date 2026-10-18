package connectip

import (
	"bytes"
	"encoding/binary"
	"math"
	"net/netip"
	"testing"

	"github.com/apernet/quic-go/quicvarint"
)

func testIPv4Packet() []byte {
	b := make([]byte, 36)
	b[0] = 0x46 // IPv4 with a 24-byte header
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[8], b[9] = 64, 6
	copy(b[12:16], []byte{172, 16, 0, 2})
	copy(b[16:20], []byte{8, 8, 8, 8})
	return b
}

func TestWritePacketBufferFraming(t *testing.T) {
	for _, mode := range []string{"h3", "h2", "cloudflare-h2"} {
		for _, offset := range []int{0, 16} {
			for _, original := range [][]byte{testIPv4Packet(), testIPv6Packet()} {
				sink := &packetEncodingSink{}
				c := &Conn{str: sink, bare: mode == "cloudflare-h2"}
				if mode == "h3" {
					c.h3 = sink
				}
				buf := bytes.Repeat([]byte{0xa5}, offset+len(original)+8)
				copy(buf[offset:], original)
				if icmp, err := c.WritePacketBuffer(buf, offset, len(original)); err != nil || len(icmp) > 0 {
					t.Fatalf("%s offset=%d: ICMP=%d err=%v", mode, offset, len(icmp), err)
				}
				packet := buf[offset : offset+len(original)]
				if original[0]>>4 == 4 {
					if packet[8] != 63 || binary.BigEndian.Uint16(packet[10:12]) != calculateIPv4Checksum(packet[:24]) {
						t.Fatal("lost IPv4 TTL/checksum update")
					}
				} else if packet[7] != 63 {
					t.Fatal("lost IPv6 hop limit update")
				}
				var expected []byte
				contextSize := 1
				if c.bare {
					contextSize = 0
				}
				if mode != "h3" {
					expected = quicvarint.Append(expected, 0)
					expected = quicvarint.Append(expected, uint64(len(packet)+contextSize))
				}
				if contextSize > 0 {
					expected = append(expected, 0)
				}
				expected = append(expected, packet...)
				if !bytes.Equal(sink.data[:sink.n], expected) {
					t.Fatalf("%s offset=%d: invalid framing", mode, offset)
				}
				if !bytes.Equal(buf[offset+len(original):], bytes.Repeat([]byte{0xa5}, 8)) {
					t.Fatal("wrote past the packet")
				}
			}
		}
	}
}

func TestWritePacketBufferRejectsInvalidBounds(t *testing.T) {
	c := &Conn{}
	for _, bounds := range [][2]int{{-1, 0}, {0, -1}, {2, 0}, {1, math.MaxInt}, {math.MaxInt, 1}} {
		if _, err := c.WritePacketBuffer([]byte{0}, bounds[0], bounds[1]); err == nil {
			t.Fatalf("accepted bounds %v", bounds)
		}
	}
}

func testIPv6Packet() []byte {
	b := make([]byte, 72)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-40))
	b[6], b[7] = 6, 64
	s := netip.MustParseAddr("2606:4700:110::1").As16()
	d := netip.MustParseAddr("2404:6800:400b:c006::8b").As16()
	copy(b[8:24], s[:])
	copy(b[24:40], d[:])
	return b
}

func TestIPv4OutboundCapsuleWithoutRemoteRoute(t *testing.T) {
	// Cloudflare doesn't advertise arbitrary remote routes; outbound packets
	// must not be rejected just for missing peer ROUTE_ADVERTISEMENT.
	c := &Conn{}
	b := testIPv4Packet()
	wire, err := c.composeDatagram(b)
	if err != nil {
		t.Fatal(err)
	}
	typ, n, err := quicvarint.Parse(wire)
	if err != nil || typ != 0 {
		t.Fatalf("capsule type=%d: %v", typ, err)
	}
	length, k, err := quicvarint.Parse(wire[n:])
	if err != nil || int(length) != len(b)+1 {
		t.Fatalf("capsule length=%d: %v", length, err)
	}
	data := wire[n+k:]
	if data[0] != 0 || !bytes.Equal(data[1:], b) {
		t.Fatal("IP context ID or payload modified")
	}
	if b[8] != 63 || binary.BigEndian.Uint16(b[10:12]) != calculateIPv4Checksum(b[:24]) {
		t.Fatal("IPv4 TTL or checksum was not updated")
	}
}

func TestIPv6OutboundCapsuleAndIncomingRoute(t *testing.T) {
	c := &Conn{}
	b := testIPv6Packet()
	wire, err := c.composeDatagram(b)
	if err != nil {
		t.Fatal(err)
	}
	_, n, err := quicvarint.Parse(wire)
	if err != nil {
		t.Fatal(err)
	}
	_, k, err := quicvarint.Parse(wire[n:])
	if err != nil {
		t.Fatal(err)
	}
	if b[7] != 63 || wire[n+k] != 0 || !bytes.Equal(wire[n+k+1:], b) {
		t.Fatal("IPv6 Hop Limit or context encoding was incorrect")
	}
	if err := c.handleIncomingProxiedPacket(b); err == nil {
		t.Fatal("incoming packets without an advertised local route must be rejected")
	}
	c.localRoutes = []IPRoute{{StartIP: netip.IPv6Unspecified(), EndIP: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")}}
	if err := c.handleIncomingProxiedPacket(b); err != nil {
		t.Fatal(err)
	}
}

func TestMalformedOutboundPackets(t *testing.T) {
	for _, b := range [][]byte{
		nil, {0x70}, {0x45}, append([]byte{0x44}, make([]byte, 19)...),
		append([]byte{0x4f}, make([]byte, 19)...),
		{0x60}, func() []byte { b := testIPv6Packet(); b[7] = 1; return b }(),
		func() []byte { b := testIPv4Packet(); b[8] = 1; return b }(),
	} {
		if _, err := (&Conn{}).composeDatagram(b); err == nil {
			t.Fatalf("accepted invalid packet %x", b)
		}
	}
}

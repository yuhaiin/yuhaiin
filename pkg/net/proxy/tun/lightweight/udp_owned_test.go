package lightweight

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// Verify the wire format both at the MTU boundary and after fragmentation.
// In particular, fragments share one ID, clear IPv4 DF, and retain the
// original UDP payload and transport checksum across IPv4 and IPv6.
func TestUDPOwnedPacketWireFormat(t *testing.T) {
	writer, reader := memoryPair()
	s, err := New(Config{
		MTU: 1280,
		Addresses: []netip.Addr{
			netip.MustParseAddr("192.0.2.1"),
			netip.MustParseAddr("2001:db8::1"),
		},
	}, writer)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for _, tc := range []struct {
		name string
		src, dst string
		size int
	}{
		{"ipv4 empty", "192.0.2.1:1000", "192.0.2.2:2000", 0},
		{"ipv4 exact mtu", "192.0.2.1:1000", "192.0.2.2:2000", 1252},
		{"ipv6 exact mtu", "[2001:db8::1]:1000", "[2001:db8::2]:2000", 1232},
		{"ipv4 fragmented", "192.0.2.1:1000", "192.0.2.2:2000", 4096},
		{"ipv6 fragmented", "[2001:db8::1]:1000", "[2001:db8::2]:2000", 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := netip.MustParseAddrPort(tc.src)
			dst := netip.MustParseAddrPort(tc.dst)
			data := make([]byte, tc.size)
			for i := range data {
				data[i] = byte(i)
			}
			if n, err := s.WriteUDP(src, dst, data); err != nil || n != len(data) {
				t.Fatalf("WriteUDP() = %d, %v", n, err)
			}

			h := 20
			if src.Addr().Is6() {
				h = 40
			}
			fragmented := h+8+len(data) > 1280
			chunk := 8 + len(data)
			count := 1
			if fragmented {
				fragHeader := 0
				if src.Addr().Is6() {
					fragHeader = 8
				}
				chunk = (1280 - h - fragHeader) &^ 7
				count = (8 + len(data) + chunk - 1) / chunk
			}
			assembled := make([]byte, 8+len(data))
			var fragmentID uint32
			for i := range count {
				var frame []byte
				select {
				case frame = <-reader.rx:
				case <-time.After(2 * time.Second):
					t.Fatal("timed out waiting for output frame")
				}
				if len(frame) > 1280 {
					t.Fatalf("frame exceeds MTU: %d", len(frame))
				}
				p, err := ParsePacket(frame)
				if err != nil {
					t.Fatal(err)
				}
				if p.Source != src.Addr() || p.Destination != dst.Addr() || p.Protocol != 17 {
					t.Fatalf("wrong IP endpoints/protocol: %+v", p)
				}
				if p.Fragmented != fragmented {
					t.Fatalf("unexpected fragmentation: %+v", p)
				}
				if fragmented {
					if i > 0 && fragmentID != p.FragmentID {
						t.Fatal("fragments do not share an IP identification")
					}
					fragmentID = p.FragmentID
					if p.FragmentOffset != i*chunk || p.MoreFragments != (i < count-1) {
						t.Fatalf("invalid fragment offset/flag: %+v", p)
					}
					if src.Addr().Is4() && binary.BigEndian.Uint16(frame[6:8])&0x4000 != 0 {
						t.Fatal("IPv4 fragment has DF set")
					}
					if src.Addr().Is6() && frame[41] != 0 {
						t.Fatal("IPv6 fragment reserved byte must be zero")
					}
				} else if err := p.ValidateTransport(); err != nil {
					t.Fatalf("invalid unfragmented packet: %v", err)
				}
				copy(assembled[p.FragmentOffset:], p.Payload)
			}
			if binary.BigEndian.Uint16(assembled[:2]) != src.Port() ||
				binary.BigEndian.Uint16(assembled[2:4]) != dst.Port() ||
				binary.BigEndian.Uint16(assembled[4:6]) != uint16(len(assembled)) ||
				transportChecksum(src.Addr(), dst.Addr(), 17, assembled) != 0 ||
				!bytes.Equal(assembled[8:], data) {
				t.Fatal("reassembled UDP datagram differs from input")
			}
		})
	}
}

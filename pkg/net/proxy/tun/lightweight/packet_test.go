package lightweight

import (
	"encoding/hex"
	"net/netip"
	"testing"
)

func TestParseIPv4Reference(t *testing.T) {
	// Independently specified IPv4/UDP packet: the IPv4 UDP checksum is optional.
	b, err := hex.DecodeString("450000200001000040118e95c0000201c633640204d20035000c000074657374")
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePacket(b)
	if err != nil {
		t.Fatal(err)
	}
	if p.Source != netip.MustParseAddr("192.0.2.1") || p.Destination != netip.MustParseAddr("198.51.100.2") || p.HopLimit != 64 || p.Protocol != 17 {
		t.Fatalf("packet: %+v", p)
	}
	if err := p.ValidateTransport(); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, 19, 25, 31} {
		if _, err := ParsePacket(b[:n]); err == nil {
			t.Fatalf("accepted truncated size %d", n)
		}
	}
	b[10] ^= 1
	if _, err := ParsePacket(b); err == nil {
		t.Fatal("accepted invalid checksum")
	}
}

func FuzzParsePacket(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 40))
	v4, _ := hex.DecodeString("450000200001000040118e95c0000201c633640204d20035000c000074657374")
	f.Add(v4)
	v6, _ := hex.DecodeString("600000000008114020010db800000000000000000000000120010db80000000000000000000000020035005000080000")
	f.Add(v6)
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParsePacket(b)
		if err == nil && !p.Fragmented {
			_ = p.ValidateTransport()
		}
	})
}

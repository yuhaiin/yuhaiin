package lightweight

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func TestVerifiedChecksumStillValidatesStructure(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.1:1000")
	dst := netip.MustParseAddrPort("192.0.2.2:2000")
	b := wireTCP(src, dst, 1, 1, flagACK, 4096, nil, []byte("payload"))
	b[len(b)-1] ^= 1
	p, err := ParsePacket(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ValidateTransport(); !errors.Is(err, ErrChecksum) {
		t.Fatalf("wire checksum bypassed: %v", err)
	}
	if err := p.validateTransport(true); err != nil {
		t.Fatalf("trusted partial packet: %v", err)
	}
	for _, offset := range []byte{0x40, 0xf0} {
		p.Payload[12] = offset
		if err := p.validateTransport(true); !errors.Is(err, ErrMalformed) {
			t.Fatalf("trusted invalid TCP offset: %v", err)
		}
	}
	b[10] ^= 1
	if _, err := ParsePacket(b); !errors.Is(err, ErrChecksum) {
		t.Fatalf("trusted path must still reject corrupt IP headers: %v", err)
	}
	udp := Packet{Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"), Protocol: 17, Payload: make([]byte, 8)}
	binary.BigEndian.PutUint16(udp.Payload[4:6], 8)
	if err := udp.ValidateTransport(); !errors.Is(err, ErrChecksum) {
		t.Fatalf("IPv6 wire UDP zero checksum: %v", err)
	}
	if err := udp.validateTransport(true); err != nil {
		t.Fatal(err)
	}
	udp.Payload[5]++
	if err := udp.validateTransport(true); !errors.Is(err, ErrMalformed) {
		t.Fatalf("trusted invalid UDP length: %v", err)
	}
	udp.Fragmented = true
	if err := udp.validateTransport(true); !errors.Is(err, ErrMalformed) {
		t.Fatal("fragment accepted before reassembly")
	}
}

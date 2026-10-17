package masque

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/quic-go/quic-go"
)

type captureCloudflareDatagrams struct {
	datagrams [][]byte
	err       error
}

func (c *captureCloudflareDatagrams) SendDatagram(b []byte) error {
	if c.err != nil {
		return c.err
	}
	c.datagrams = append(c.datagrams, bytes.Clone(b))
	return nil
}

func makeCloudflareIPv4Packet() []byte {
	// Include four bytes of IPv4 options to exercise full-IHL checksumming.
	packet := make([]byte, 36)
	packet[0] = 0x46
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 6 // TCP
	copy(packet[12:16], []byte{172, 16, 0, 2})
	copy(packet[16:20], []byte{8, 8, 8, 8})
	copy(packet[20:24], []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(packet[10:12], cloudflareIPv4Checksum(packet[:24]))
	return packet
}

func makeCloudflareIPv6Packet() []byte {
	packet := make([]byte, 72)
	packet[0] = 6 << 4
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	packet[6] = 6 // TCP, without any remote route advertisement
	packet[7] = 64
	src := netip.MustParseAddr("2606:4700:110::1")
	dst := netip.MustParseAddr("2404:6800:400b:c006::8b")
	src16 := src.As16()
	dst16 := dst.As16()
	copy(packet[8:24], src16[:])
	copy(packet[24:40], dst16[:])
	return packet
}

func TestSendCloudflareIPPacketWithoutPeerRoute(t *testing.T) {
	t.Run("IPv6 TCP Internet destination", func(t *testing.T) {
		sender := &captureCloudflareDatagrams{}
		packet := makeCloudflareIPv6Packet()
		icmp, err := sendCloudflareIPPacket(sender, packet)
		if err != nil || len(icmp) != 0 {
			t.Fatalf("send = (%x, %v), want no error or ICMP", icmp, err)
		}
		if len(sender.datagrams) != 1 {
			t.Fatalf("sent %d datagrams, want 1", len(sender.datagrams))
		}
		datagram := sender.datagrams[0]
		if datagram[0] != cloudflareIPContextID {
			t.Fatalf("context ID = %d, want 0", datagram[0])
		}
		if len(datagram) != len(packet)+1 || !bytes.Equal(datagram[1:], packet) {
			t.Fatal("outgoing datagram did not preserve the IPv6 packet")
		}
		if packet[7] != 63 {
			t.Fatalf("hop limit = %d, want 63", packet[7])
		}
		wantDest := netip.MustParseAddr("2404:6800:400b:c006::8b").As16()
		if !bytes.Equal(datagram[25:41], wantDest[:]) {
			t.Fatal("outgoing IPv6 destination was modified")
		}
	})

	t.Run("IPv4 TCP with options", func(t *testing.T) {
		sender := &captureCloudflareDatagrams{}
		packet := makeCloudflareIPv4Packet()
		_, err := sendCloudflareIPPacket(sender, packet)
		if err != nil {
			t.Fatal(err)
		}
		if len(sender.datagrams) != 1 {
			t.Fatal("IPv4 packet was not forwarded")
		}
		if packet[8] != 63 {
			t.Fatalf("TTL = %d, want 63", packet[8])
		}
		if sum := cloudflareIPv4Checksum(packet[:24]); sum != 0 {
			t.Fatalf("IPv4 checksum invalid after TTL update: %#x", sum)
		}
		if !bytes.Equal(sender.datagrams[0][1:], packet) {
			t.Fatal("IPv4 datagram payload differs from outgoing packet")
		}
	})
}

func TestSendCloudflareIPPacketRejectsMalformedPackets(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
	}{
		{"empty", nil},
		{"wrong version", []byte{0x70}},
		{"truncated IPv4", []byte{0x45}},
		{"IPv4 invalid IHL", append([]byte{0x44}, make([]byte, 19)...)},
		{"IPv4 IHL exceeds packet", append([]byte{0x4f}, make([]byte, 19)...)},
		{"IPv4 expired TTL", func() []byte { b := makeCloudflareIPv4Packet(); b[8] = 1; return b }()},
		{"truncated IPv6", []byte{0x60}},
		{"IPv6 expired hop limit", func() []byte { b := makeCloudflareIPv6Packet(); b[7] = 1; return b }()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sender := &captureCloudflareDatagrams{}
			icmp, err := sendCloudflareIPPacket(sender, tc.packet)
			if err != nil || icmp != nil || len(sender.datagrams) != 0 {
				t.Fatalf("invalid packet was sent or returned an error: ICMP=%x err=%v datagrams=%d", icmp, err, len(sender.datagrams))
			}
		})
	}
}

func TestSendCloudflareIPPacketDatagramTooLarge(t *testing.T) {
	for _, packet := range [][]byte{makeCloudflareIPv4Packet(), makeCloudflareIPv6Packet()} {
		sender := &captureCloudflareDatagrams{err: &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1200}}
		icmp, err := sendCloudflareIPPacket(sender, packet)
		if err != nil {
			t.Fatal(err)
		}
		if len(icmp) == 0 {
			t.Fatal("expected ICMP Packet Too Big response")
		}
		if packet[0]>>4 == 4 {
			if icmp[0]>>4 != 4 || icmp[9] != 1 || icmp[20] != 3 || icmp[21] != 4 {
				t.Fatalf("invalid IPv4 fragmentation needed ICMP response: %x", icmp[:min(len(icmp), 28)])
			}
			if !bytes.Equal(icmp[12:16], packet[16:20]) || !bytes.Equal(icmp[16:20], packet[12:16]) {
				t.Fatal("ICMPv4 addresses were not swapped")
			}
		} else {
			if icmp[0]>>4 != 6 || icmp[6] != 58 || icmp[40] != 2 {
				t.Fatalf("invalid ICMPv6 Packet Too Big response: %x", icmp[:min(len(icmp), 48)])
			}
			if !bytes.Equal(icmp[8:24], packet[24:40]) || !bytes.Equal(icmp[24:40], packet[8:24]) {
				t.Fatal("ICMPv6 addresses were not swapped")
			}
		}
	}
}

func TestSendCloudflareIPPacketPropagatesTransportError(t *testing.T) {
	down := errors.New("QUIC connection closed")
	sender := &captureCloudflareDatagrams{err: down}
	_, err := sendCloudflareIPPacket(sender, makeCloudflareIPv6Packet())
	if !errors.Is(err, down) {
		t.Fatalf("got %v, want transport error", err)
	}
}

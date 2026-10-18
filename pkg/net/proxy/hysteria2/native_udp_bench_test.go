package hysteria2

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/hysteria2/internal/wire"
	"github.com/apernet/quic-go"
)

type datagramSink struct {
	scratch  [1200]byte
	tooLarge quic.DatagramTooLargeError
}

func (s *datagramSink) SendDatagram(b []byte) error {
	if len(b) > len(s.scratch) {
		return &s.tooLarge
	}
	copy(s.scratch[:], b)
	return nil
}

func BenchmarkNativeDatagramEncoding(b *testing.B) {
	for _, size := range []int{1000, 8192, 65535} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			sink := &datagramSink{tooLarge: quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1200}}
			msg := wire.UDPMessage{SessionID: 1, PacketID: 42, FragmentCount: 1, Address: "example.com:53", Data: bytes.Repeat([]byte{1}, size)}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				if err := sendNativeDatagram(sink, msg); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestNativeDatagramPreservesPacketID(t *testing.T) {
	sink := &datagramSink{tooLarge: quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1200}}
	msg := wire.UDPMessage{SessionID: 1, PacketID: 42, FragmentCount: 1, Address: "example.com:53", Data: make([]byte, 8192)}
	if err := sendNativeDatagram(sink, msg); err != nil {
		t.Fatal(err)
	}
	// All fragments must retain the session's monotonically increasing ID.
	// The old random ID was forced odd, reducing the namespace by half.
	if got := uint16(sink.scratch[4])<<8 | uint16(sink.scratch[5]); got != msg.PacketID {
		t.Fatalf("packet ID=%d, want %d", got, msg.PacketID)
	}
}

package connectip

import (
	"encoding/binary"
	"testing"
)

type packetEncodingSink struct {
	blockedDatagramStream
	data [2048]byte
	n    int
}

func (s *packetEncodingSink) SendDatagram(b []byte) error { s.n = copy(s.data[:], b); return nil }

func (s *packetEncodingSink) Write(b []byte) (int, error) {
	s.n = copy(s.data[:], b)
	return len(b), nil
}

func benchmarkPacket() []byte {
	b := make([]byte, 1200)
	b[0], b[8], b[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	return b
}

func BenchmarkPacketEncoding(b *testing.B) {
	for _, headroom := range []bool{false, true} {
		name := "Copy"
		if headroom {
			name = "Headroom"
		}
		b.Run(name, func(b *testing.B) { benchmarkPacketEncoding(b, headroom) })
	}
}

func benchmarkPacketEncoding(b *testing.B, headroom bool) {
	sink := &packetEncodingSink{}
	c := &Conn{h3: sink}
	buf := make([]byte, 16+1200)
	copy(buf[16:], benchmarkPacket())
	packet := buf[16:]
	b.SetBytes(int64(len(packet)))
	b.ReportAllocs()
	for b.Loop() {
		packet[8] = 64
		var err error
		if headroom {
			_, err = c.WritePacketBuffer(buf, 16, len(packet))
		} else {
			_, err = c.WritePacket(packet)
		}
		if err != nil {
			b.Fatal(err)
		}
	}
}

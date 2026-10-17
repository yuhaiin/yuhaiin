package device

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestVirtioLegacyUDPZeroChecksum(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		ih := 20
		if v6 {
			ih = 40
		}
		b := make([]byte, 10+ih+8)
		p := b[10:]
		if v6 {
			p[0], p[6] = 0x60, 17
			binary.BigEndian.PutUint16(p[4:], 8)
		} else {
			p[0], p[9] = 0x45, 17
			binary.BigEndian.PutUint16(p[2:], 28)
		}
		// Zero addresses give a pseudo-header sum of 17+8. Choose a port so the
		// completed checksum is zero; UDP must put 0xffff on the wire instead.
		binary.BigEndian.PutUint16(p[ih:], 65502)
		binary.BigEndian.PutUint16(p[ih+4:], 8)
		binary.BigEndian.PutUint16(p[ih+6:], 25)
		b[0] = unix.VIRTIO_NET_HDR_F_NEEDS_CSUM
		binary.LittleEndian.PutUint16(b[6:], uint16(ih))
		binary.LittleEndian.PutUint16(b[8:], 6)
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		d := &offloadTUN{file: reader, prefix: 10, mtu: 1500}
		t.Cleanup(func() { _ = d.Close(); _ = writer.Close() })
		if _, err := writer.Write(b); err != nil {
			t.Fatal(err)
		}
		out := make([]byte, len(b))
		sizes := []int{0}
		if n, err := d.Read([][]byte{out}, sizes); n != 1 || err != nil {
			t.Fatalf("read=%d %v", n, err)
		}
		if got := binary.BigEndian.Uint16(out[10+ih+6:]); got != 0xffff {
			t.Fatalf("UDP checksum=%04x", got)
		}
	}
}

func virtioTCP(v6 bool) []byte {
	ih := 20
	if v6 {
		ih = 40
	}
	b := make([]byte, 10+ih+20+4000)
	p := b[10:]
	if v6 {
		p[0], p[6] = 0x60, 6
		binary.BigEndian.PutUint16(p[4:], uint16(len(p)-40))
	} else {
		p[0], p[9] = 0x45, 6
		binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	}
	p[ih+12], p[ih+13] = 0x50, 0x18
	return b
}

func TestVirtioTCPMetadata(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		b := virtioTCP(v6)
		if err := encodeVirtioTCP(b[:10], b[10:], 1400, 1500); err != nil {
			t.Fatal(err)
		}
		if p, verified, err := decodeVirtioPacket(b, 10); err != nil || !verified || len(p) != len(b)-10 {
			t.Fatalf("valid GSO: verified=%v err=%v", verified, err)
		}
		for name, mutate := range map[string]func([]byte){
			"flags":           func(p []byte) { p[0] |= 0x80 },
			"checksum-start":  func(p []byte) { p[6]++ },
			"checksum-offset": func(p []byte) { p[8]++ },
			"zero-mss":        func(p []byte) { clear(p[4:6]) },
			"short-header":    func(p []byte) { clear(p[2:4]) },
			"long-header":     func(p []byte) { p[3] = 0xff },
			"wrong-family":    func(p []byte) { p[1] ^= 5 },
			"missing-partial": func(p []byte) { p[0] = unix.VIRTIO_NET_HDR_F_DATA_VALID },
			"transport-length": func(p []byte) {
				if v6 {
					p[14]++
				} else {
					p[12]++
				}
			},
		} {
			t.Run(name, func(t *testing.T) {
				p := append([]byte(nil), b...)
				mutate(p)
				if _, _, err := decodeVirtioPacket(p, 10); !errors.Is(err, io.ErrShortBuffer) {
					t.Fatalf("accepted invalid metadata: %v", err)
				}
			})
		}
		for _, size := range []int{-1, 0, 1500, 65536} {
			if err := encodeVirtioTCP(b[:10], b[10:], size, 1500); err == nil {
				t.Fatalf("accepted MSS %d", size)
			}
		}
		ih := 20
		if v6 {
			ih = 40
		}
		b[10+ih+13] |= 2
		if err := encodeVirtioTCP(b[:10], b[10:], 1400, 1500); err == nil {
			t.Fatal("segmented a SYN")
		}
	}
}

func FuzzVirtioPacket(f *testing.F) {
	f.Add([]byte{}, 10)
	for _, v6 := range []bool{false, true} {
		b := virtioTCP(v6)
		_ = encodeVirtioTCP(b[:10], b[10:], 1400, 1500)
		f.Add(b, 10)
	}
	f.Fuzz(func(t *testing.T, b []byte, prefix int) {
		p, verified, err := decodeVirtioPacket(b, prefix)
		if err == nil && verified {
			if _, _, _, _, err := packetTransport(p); err != nil {
				t.Fatal("trusted malformed transport")
			}
		}
		header := make([]byte, 10)
		_ = encodeVirtioTCP(header, b, prefix, 1500)
	})
}

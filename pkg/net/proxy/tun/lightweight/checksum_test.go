package lightweight

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

func TestChecksumReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for _, size := range []int{0, 1, 2, 3, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1500, 65535, 65536, 65537, 65575, 65600, 1 << 20} {
		for _, fill := range []byte{0, 0xff, 0xa5} {
			data := bytes.Repeat([]byte{fill}, size+64)
			for offset := range 64 {
				b := data[offset : offset+size]
				if got, want := Checksum(b), ^checksum.Checksum(b, 0); got != want {
					t.Fatalf("size=%d offset=%d fill=%x: %x != %x", size, offset, fill, got, want)
				}
			}
		}
		data := make([]byte, size+64)
		for i := range data {
			data[i] = byte(rng.Uint32())
		}
		for offset := range 64 {
			b := data[offset : offset+size]
			initial := uint16(rng.Uint32())
			if got, want := fold(sumBytes(b, uint32(initial))), checksum.Checksum(b, initial); got != want {
				t.Fatalf("seeded size=%d offset=%d: %x != %x", size, offset, got, want)
			}
		}
	}
}

func FuzzChecksum(f *testing.F) {
	for _, n := range []int{0, 1, 127, 128, 129, 65535, 65536, 65537} {
		f.Add(bytes.Repeat([]byte{0xff}, n), uint16(65535))
	}
	f.Fuzz(func(t *testing.T, b []byte, initial uint16) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		want := checksum.Checksum(b, initial)
		if got := fold(sumBytes(b, uint32(initial))); got != want {
			t.Fatalf("native=%04x want=%04x len=%d seed=%04x", got, want, len(b), initial)
		}
	})
}

func BenchmarkChecksum(b *testing.B) {
	for _, size := range []int{40, 1500, 65535} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			data := bytes.Repeat([]byte{0xa5}, size+1)[1:]
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				Checksum(data)
			}
		})
	}
}

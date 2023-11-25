package checksum

import (
	"crypto/rand"
	"fmt"
	"io"
	mrand "math/rand"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

const (
	chunkSize  = 9000
	chunkCount = 10
)

func BenchmarkChecksum(b *testing.B) {
	var bufSizes = []int{64, 128, 256, 512, 1024, 1500, 2048, 4096, 8192, 16384, 32767, 32768, 65535, 65536}

	checkSumImpls := []struct {
		fn   func([]byte) uint32
		name string
	}{
		{unrolledSumCompat, "unrolledsumCompat"},
		{sumCompat, "sumCompat"},
	}

	for _, csumImpl := range checkSumImpls {
		// Ensure same buffer generation for test consistency.
		rnd := mrand.New(mrand.NewSource(42))
		for _, bufSz := range bufSizes {
			b.Run(fmt.Sprintf("%s_%d", csumImpl.name, bufSz), func(b *testing.B) {
				tc := struct {
					buf  []byte
					csum uint32
				}{
					buf: make([]byte, bufSz),
				}
				rnd.Read(tc.buf)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					tc.csum = csumImpl.fn(tc.buf)
				}
			})
		}
	}
}

func TestXxx(t *testing.T) {
	x := 1200000000000000000

	t.Log(uint16(x), uint16(x>>16), x&0xffff)

	t.Log(checksum.Combine(uint16(x), uint16(x>>16)))

	z := make([]byte, 32)
	rand.Read(z)
	t.Log(CheckSumCombine(0, z))
	sum := CheckSumCombine(0, z[:16])
	sum = CheckSumCombine(uint32(sum), z[16:])

	t.Log(sum)
}

func TestChecksum(t *testing.T) {
	buf := make([]byte, nat.MaxSegmentSize)
	io.ReadFull(rand.Reader, buf)

	t.Log(checksum.Checksum(buf, 0))
	t.Log(CheckSumCombine(0, buf))
}

//go:build amd64 || arm64

package lightweight

import "math/bits"

const checksumAccelerated = true

func checksumBulk(b []byte, sum uint32) ([]byte, uint32) {
	// Small IP/pseudo headers stay in Go. Each bulk call reads only complete
	// 64-byte blocks and is bounded so ARM64's widened SIMD lanes cannot wrap.
	for len(b) >= 128 {
		n := min(len(b)&^63, 65536)
		v := checksumBlocks(b[:n])
		v = v&0xffffffff + v>>32
		v = v&65535 + v>>16
		v = v&65535 + v>>16
		v = v&65535 + v>>16
		// Native little-endian accumulation is equivalent after the final byte
		// swap (RFC 1071 section 2). Preserve the caller's network-order seed.
		sum = uint32(fold(sum)) + uint32(bits.ReverseBytes16(uint16(v)))
		b = b[n:]
	}
	return b, sum
}

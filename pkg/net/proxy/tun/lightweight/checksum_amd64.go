package lightweight

import (
	"encoding/binary"
	"math/bits"
)

// The compiler lowers Add64 to an ADD/ADC chain. This matches handwritten
// assembly throughput while retaining Go's ABI, bounds checks and tooling.
func checksumBlocks(b []byte) uint64 {
	var sum uint64
	for len(b) >= 64 {
		var carry uint64
		sum, carry = bits.Add64(sum, binary.LittleEndian.Uint64(b), 0)
		sum, carry = bits.Add64(sum, binary.LittleEndian.Uint64(b[8:]), carry)
		sum, carry = bits.Add64(sum, binary.LittleEndian.Uint64(b[16:]), carry)
		sum, carry = bits.Add64(sum, binary.LittleEndian.Uint64(b[24:]), carry)
		sum, carry = bits.Add64(sum, binary.LittleEndian.Uint64(b[32:]), carry)
		sum, carry = bits.Add64(sum, binary.LittleEndian.Uint64(b[40:]), carry)
		sum, carry = bits.Add64(sum, binary.LittleEndian.Uint64(b[48:]), carry)
		sum, carry = bits.Add64(sum, binary.LittleEndian.Uint64(b[56:]), carry)
		sum, _ = bits.Add64(sum, 0, carry)
		b = b[64:]
	}
	return sum
}

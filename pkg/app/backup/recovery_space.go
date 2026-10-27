package backup

import "math/bits"

func recoveryDiskBytes(blocks, size uint64) uint64 {
	high, low := bits.Mul64(blocks, size)
	if high != 0 {
		return ^uint64(0)
	}
	return low
}

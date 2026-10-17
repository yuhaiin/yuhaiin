package lightweight

// checksumBlocks sums a nonempty, 64-byte-aligned length, at most 65536 bytes.
// The data pointer may be unaligned. It must never read outside the slice.
//
//go:noescape
func checksumBlocks(b []byte) uint64

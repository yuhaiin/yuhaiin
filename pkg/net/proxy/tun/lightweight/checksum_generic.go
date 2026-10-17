//go:build !amd64 && !arm64

package lightweight

const checksumAccelerated = false

// The compile-time capability removes this call on other architectures.
func checksumBulk(b []byte, sum uint32) ([]byte, uint32) { return b, sum }

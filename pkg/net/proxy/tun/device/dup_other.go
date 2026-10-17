//go:build !linux

package device

// Legacy non-Linux callers retain their platform-specific descriptor ownership.
// The Linux-only Android fd:// implementations duplicate their borrowed input.
func duplicateTUNFD(fd int) (int, error) { return fd, nil }

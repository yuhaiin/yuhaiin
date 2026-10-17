//go:build linux

package device

// DuplicateBorrowedFD is also used by gVisor's fdbased endpoint, which
// bypasses the ordinary netlink.Tun device wrapper.
func DuplicateBorrowedFD(fd int) (int, error) { return duplicateTUNFD(fd) }

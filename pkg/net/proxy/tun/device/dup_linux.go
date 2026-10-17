//go:build linux

package device

import "golang.org/x/sys/unix"

// duplicateTUNFD gives the native stack an independently owned descriptor.
// F_DUPFD_CLOEXEC atomically prevents leaking this handle across exec.
func duplicateTUNFD(fd int) (int, error) {
	return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
}

// DuplicateBorrowedFD is also used by gVisor's fdbased endpoint, which
// bypasses the ordinary netlink.Tun device wrapper.
func DuplicateBorrowedFD(fd int) (int, error) { return duplicateTUNFD(fd) }

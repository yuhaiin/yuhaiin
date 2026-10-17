//go:build linux || (unix && !aix && !ppc64)

package device

import "golang.org/x/sys/unix"

// duplicateTUNFD gives the native stack an independently owned descriptor.
// F_DUPFD_CLOEXEC atomically prevents leaking this handle across exec.
func duplicateTUNFD(fd int) (int, error) {
	return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
}

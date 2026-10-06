//go:build !android

package netlink

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

var defaultProcSearchCalls = procSearchCalls{
	openat: func(fd int, name []byte) (int, error) {
		r, _, errno := unix.Syscall6(unix.SYS_OPENAT, uintptr(fd),
			uintptr(unsafe.Pointer(unsafe.SliceData(name))),
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_LARGEFILE, 0, 0, 0)
		if errno != 0 {
			return -1, errno
		}
		return int(r), nil
	},
	readlinkat: func(fd int, name, buf []byte) (int, error) {
		r, _, errno := unix.Syscall6(unix.SYS_READLINKAT, uintptr(fd),
			uintptr(unsafe.Pointer(unsafe.SliceData(name))),
			uintptr(unsafe.Pointer(unsafe.SliceData(buf))), uintptr(len(buf)), 0, 0)
		if errno != 0 {
			return 0, errno
		}
		return int(r), nil
	},
}

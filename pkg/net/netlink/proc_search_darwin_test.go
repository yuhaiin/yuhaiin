package netlink

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// Test-only libSystem adapters let the Linux proc scanner and its allocation
// budget run on macOS directory fixtures. The existing x/sys trampolines use
// the native calling convention; Linux uses openat/readlinkat syscalls.
//
//go:linkname procTestOpenatAddr golang.org/x/sys/unix.libc_openat_trampoline_addr
var procTestOpenatAddr uintptr

//go:linkname procTestReadlinkatAddr golang.org/x/sys/unix.libc_readlinkat_trampoline_addr
var procTestReadlinkatAddr uintptr

var defaultProcSearchCalls = procSearchCalls{
	openat: func(fd int, name []byte) (int, error) {
		r, _, errno := pcbLibcCall6(procTestOpenatAddr, uintptr(fd),
			uintptr(unsafe.Pointer(unsafe.SliceData(name))),
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0, 0, 0)
		if errno != 0 {
			return -1, errno
		}
		return int(r), nil
	},
	readlinkat: func(fd int, name, buf []byte) (int, error) {
		r, _, errno := pcbLibcCall6(procTestReadlinkatAddr, uintptr(fd),
			uintptr(unsafe.Pointer(unsafe.SliceData(name))),
			uintptr(unsafe.Pointer(unsafe.SliceData(buf))), uintptr(len(buf)), 0, 0)
		if errno != 0 {
			return 0, errno
		}
		return int(r), nil
	},
}

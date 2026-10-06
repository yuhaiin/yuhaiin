package netlink

import (
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	readTCPPCB = newPCBReader("net.inet.tcp.pcblist_n")
	readUDPPCB = newPCBReader("net.inet.udp.pcblist_n")
)

// Use the same libSystem calling convention as x/sys/unix, whose exported
// SysctlRaw does not accept caller-owned storage. This also works without CGO.
//
//go:linkname pcbLibcCall6 syscall.syscall6
//go:uintptrescapes
func pcbLibcCall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

//go:cgo_import_dynamic pcb_libc_sysctl sysctl "/usr/lib/libSystem.B.dylib"

var pcbSysctlAddr uintptr

// SysctlRaw always allocates an entire table. Resolve the numeric name once,
// then read the live table into a caller-owned buffer instead.
func newPCBReader(name string) func([]byte) ([]byte, error) {
	resolve := sync.OnceValues(func() ([]int32, error) {
		var mib [unix.CTL_MAXNAME + 2]int32
		n := uintptr(unix.CTL_MAXNAME * 4)
		key := []byte(name)
		_, _, errno := pcbLibcCall6(pcbSysctlAddr,
			uintptr(unsafe.Pointer(&[2]int32{0, 3})), 2,
			uintptr(unsafe.Pointer(&mib[0])), uintptr(unsafe.Pointer(&n)),
			uintptr(unsafe.Pointer(&key[0])), uintptr(len(key)))
		if errno != 0 {
			return nil, errno
		}
		if n == 0 || n%4 != 0 || n > uintptr(len(mib)*4) {
			return nil, unix.EIO
		}
		return mib[:n/4], nil
	})
	return func(buf []byte) ([]byte, error) {
		mib, err := resolve()
		if err != nil {
			return buf[:0], err
		}
		return readPCBTable(buf, func(data []byte, n *uintptr) error {
			_, _, errno := pcbLibcCall6(pcbSysctlAddr,
				uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)),
				uintptr(unsafe.Pointer(unsafe.SliceData(data))), uintptr(unsafe.Pointer(n)), 0, 0)
			if errno != 0 {
				return errno
			}
			return nil
		})
	}
}

func readPCBTable(buf []byte, read func([]byte, *uintptr) error) ([]byte, error) {
	// Sockets can appear between the size query and the read. Retry ENOMEM
	// with a fresh size; never publish a partial table to process matching.
	for range 3 {
		var n uintptr
		if err := read(nil, &n); err != nil {
			return buf[:0], err
		}
		if n == 0 {
			return buf[:0], nil
		}
		if n > uintptr(cap(buf)) {
			// Round up so small changes in the socket count do not allocate.
			buf = make([]byte, (n+16383)&^16383)
		}
		buf = buf[:cap(buf)]
		n = uintptr(len(buf))
		err := read(buf, &n)
		if err == unix.ENOMEM {
			continue
		}
		if err != nil {
			return buf[:0], err
		}
		if n > uintptr(len(buf)) {
			return buf[:0], unix.EIO
		}
		return buf[:n], nil
	}
	return buf[:0], unix.ENOMEM
}

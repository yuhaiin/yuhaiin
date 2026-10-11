//go:build darwin

package dataplane

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// The macOS data path: utun.
//
// Sixteen protocols, both roles, all of them usable only on Linux. For the
// server that is a defensible scope. For the client it is the difference
// between a VPN people use and a VPN people read about: the machines that dial
// a VPN are laptops, and most laptops are not Linux.
//
// utun is a kernel control socket rather than a device node — socket(AF_SYSTEM,
// SOCK_DGRAM, SYSPROTO_CONTROL), a CTLIOCGINFO ioctl to turn the control name
// "com.apple.net.utun_control" into an id, then connect(2) with that id and a
// unit number. Everything it needs is in x/sys/unix already, so this costs no
// cgo and no new dependency, and the thesis at the top of the README is intact.
//
// # The AF header
//
// Every packet read from or written to a utun carries a 4-octet big-endian
// address family in front of it: AF_INET or AF_INET6. Linux's IFF_NO_PI exists
// precisely to turn the equivalent Linux header off, and this tree relies on
// that — the pump hands Read's buffer straight to a Tunnel, and every parser
// returns subslices of its input.
//
// So the header is stripped on read and prepended on write, here, and the
// pump never learns it exists. The alternative — teaching the pump about a
// per-platform prefix — would put a platform conditional on the hottest path in
// the tree to save one copy on write, which is not a trade worth making.
//
// # What is not here
//
// GSO. It is a Linux offload (virtio-net headers on the TUN), and utun has no
// equivalent, so GSO() is false and OpenTUNGSO falls back to OpenTUN — which is
// exactly what the pump already does for any device that reports no GSO.
//
// TAP. macOS has no in-kernel TAP; the layer-2 protocols (SoftEther, L2TPv3)
// need a third-party kext, which costs the "no runtime dependencies" claim in
// the same way wintun does. OpenTAP therefore says so rather than pretending.

// Constants x/sys/unix does not export, spelled out with the header they come
// from. Both are stable ABI: changing either would break every VPN client on
// macOS, so they are safe to hard-code, and hard-coding them is what keeps this
// file free of cgo.
const (
	// utunControlName is the kernel control the utun driver registers under,
	// from <net/if_utun.h>. It is looked up by name rather than by a numeric id
	// because the id is assigned at registration and is not stable.
	utunControlName = "com.apple.net.utun_control"
	// sysprotoControl is SYSPROTO_CONTROL, <sys/kern_control.h>.
	sysprotoControl = 2
	// utunOptIfname is UTUN_OPT_IFNAME, <net/if_utun.h>: the getsockopt that
	// reads back which utunN the kernel gave us.
	utunOptIfname = 2
	// utunAFHeaderLen is the 4-octet address family every utun packet carries.
	utunAFHeaderLen = 4
)

// TUN is a macOS utun interface.
type TUN struct {
	virtual VirtualPacketIO
	fd      int
	name    string

	// closed is the latch a parked reader observes. macOS has no eventfd, so
	// Close shuts the socket down (SHUT_RDWR) to wake a blocking read rather
	// than signalling a second descriptor — a shutdown socket returns from
	// recv immediately and stays returned, which is the property the Linux
	// eventfd is chosen for.
	closed atomic.Bool

	// mu guards the validity of fd, not access to the device: Read and Write
	// hold it for reading across their syscalls, Close takes it exclusively.
	// Without it a reader between its check and its syscall can be handed a
	// descriptor number Close has already released and the kernel has reissued
	// to something else.
	mu sync.RWMutex

	// readBuf holds the AF header plus the packet, so Read can strip the header
	// without a second buffer. It belongs to the single reader goroutine, the
	// same ownership the pump's other scratch buffers have.
	readBuf []byte
	// writeBuf is the same for the write side: the header and the packet have
	// to reach the kernel in one write, and a utun does not take a writev of
	// the two.
	writeBuf []byte
}

// OpenTUN opens a utun interface. name selects the unit: "utun7" asks for unit
// 7, and an empty name takes the first free one, which is what the Linux side's
// empty name does.
//
// It needs root. There is no capability equivalent to CAP_NET_ADMIN on macOS,
// so the "grant the binary the capability once" path the README describes for
// Linux has no counterpart and the docs say so.
func OpenTUN(name string) (*TUN, error) {
	if v, ok := consumeVirtualTUN(name); ok {
		return &TUN{name: name, virtual: v}, nil
	}
	unit, err := utunUnit(name)
	if err != nil {
		return nil, err
	}

	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("dataplane: utun socket: %w (need root)", err)
	}

	// CTLIOCGINFO turns the control's name into the numeric id connect wants.
	// The name is not a stable id across releases, which is why the lookup
	// exists rather than a constant.
	var info unix.CtlInfo
	copy(info.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, &info); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("dataplane: utun CTLIOCGINFO: %w", err)
	}

	// Sc_unit is one-based: unit 0 means "any free one", unit N+1 is utunN.
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: unit}); err != nil {
		_ = unix.Close(fd)
		if unit != 0 {
			return nil, fmt.Errorf("dataplane: utun connect to %s: %w (already in use?)", name, err)
		}
		return nil, fmt.Errorf("dataplane: utun connect: %w (need root)", err)
	}

	got, err := utunName(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	// Non-blocking, matching the Linux side: a read that would park
	// uninterruptibly in the kernel cannot be woken by Close.
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("dataplane: utun non-blocking: %w", err)
	}

	return &TUN{
		fd:       fd,
		name:     got,
		readBuf:  make([]byte, 65535+utunAFHeaderLen),
		writeBuf: make([]byte, 65535+utunAFHeaderLen),
	}, nil
}

// utunUnit turns an interface name into the one-based unit connect(2) wants. An
// empty name is unit 0, which asks the kernel for the first free one.
func utunUnit(name string) (uint32, error) {
	if name == "" {
		return 0, nil
	}
	var n uint32
	if _, err := fmt.Sscanf(name, "utun%d", &n); err != nil {
		return 0, fmt.Errorf("dataplane: %q is not a utun name (utun0, utun1, …); "+
			"macOS names its tunnel interfaces and does not let a caller choose freely", name)
	}
	return n + 1, nil
}

// utunName reads back the interface the kernel actually gave us, which for a
// unit-0 request is the only way to learn it — and which the caller needs,
// because every route and address it installs names the interface.
func utunName(fd int) (string, error) {
	name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil {
		return "", fmt.Errorf("dataplane: utun name: %w", err)
	}
	return name, nil
}

// OpenTUNGSO falls back to OpenTUN. GSO is a Linux offload with no utun
// equivalent, and the pump already handles a device that reports none.
func OpenTUNGSO(name string) (*TUN, error) { return OpenTUN(name) }

// OpenTAP is unsupported: macOS has no in-kernel TAP, and the third-party kexts
// that provide one cost the "no runtime dependencies" claim in the same way
// wintun does on Windows.
func OpenTAP(string) (*TUN, error) {
	return nil, fmt.Errorf("dataplane: macOS has no in-kernel TAP device, so the layer-2 " +
		"protocols (softether, l2tpv3) cannot run here; the layer-3 protocols can")
}

// GSO is always false on macOS.
func (t *TUN) GSO() bool { return false }

// Name is the interface the kernel assigned.
func (t *TUN) Name() string {
	if t != nil && t.virtual != nil {
		return t.name
	}

	if t == nil {
		return ""
	}
	return t.name
}

// Read returns one inner IP packet with the utun AF header stripped, so the
// caller sees exactly what a Linux IFF_NO_PI device gives it.
func (t *TUN) Read(buf []byte) (int, error) {
	if t.virtual != nil {
		return t.virtual.Read(buf)
	}
	for {
		t.mu.RLock()
		if t.closed.Load() {
			t.mu.RUnlock()
			return 0, os.ErrClosed
		}
		n, err := unix.Read(t.fd, t.readBuf)
		fd := t.fd
		t.mu.RUnlock()

		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			if werr := t.waitReadable(fd); werr != nil {
				return 0, werr
			}
			continue
		}
		if err != nil {
			if t.closed.Load() {
				return 0, os.ErrClosed
			}
			return 0, err
		}
		if n <= utunAFHeaderLen {
			// A packet with a header and nothing after it. Not an error worth
			// propagating -- the caller wants the next real one.
			continue
		}
		return copy(buf, t.readBuf[utunAFHeaderLen:n]), nil
	}
}

// waitReadable blocks until the socket has data or Close shuts it down. poll is
// used rather than the runtime netpoller because the descriptor is a raw
// syscall fd, exactly as on Linux.
func (t *TUN) waitReadable(fd int) error {
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(pfd, 1000)
		if t.closed.Load() {
			return os.ErrClosed
		}
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
		// Timeout: loop, so the closed check above runs again. A one-second
		// tick is the cost of macOS having no eventfd to latch.
	}
}

// Write sends one inner IP packet, prepending the AF header the kernel
// requires. The family is read from the packet's own version nibble, which is
// the only thing that can tell them apart at this layer.
func (t *TUN) Write(pkt []byte) (int, error) {
	if t.virtual != nil {
		return t.virtual.Write(pkt)
	}
	if len(pkt) == 0 {
		return 0, nil
	}
	af := uint32(unix.AF_INET)
	if pkt[0]>>4 == 6 {
		af = unix.AF_INET6
	}
	// Big-endian, and that is not a stylistic choice: the utun header is a
	// network-order address family, unlike almost everything else in a BSD
	// socket API, and writing it host-order produces a device that accepts
	// every packet and delivers none.
	t.writeBuf[0] = byte(af >> 24)
	t.writeBuf[1] = byte(af >> 16)
	t.writeBuf[2] = byte(af >> 8)
	t.writeBuf[3] = byte(af)
	n := copy(t.writeBuf[utunAFHeaderLen:], pkt)

	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed.Load() {
		return 0, os.ErrClosed
	}
	written, err := unix.Write(t.fd, t.writeBuf[:utunAFHeaderLen+n])
	if err != nil {
		return 0, err
	}
	// Report the caller's own byte count, not the wire's: every caller compares
	// it against len(pkt), and returning four more would read as a short write
	// that grew.
	if written > utunAFHeaderLen {
		return written - utunAFHeaderLen, nil
	}
	return 0, nil
}

// Close shuts the socket down and closes it. The shutdown is what wakes a
// parked reader, in place of the eventfd the Linux side latches.
func (t *TUN) Close() error {
	if t.virtual != nil {
		return t.virtual.Close()
	}
	if t == nil {
		return nil
	}
	if !t.closed.CompareAndSwap(false, true) {
		return nil
	}
	_ = unix.Shutdown(t.fd, unix.SHUT_RDWR)
	t.mu.Lock()
	defer t.mu.Unlock()
	return unix.Close(t.fd)
}

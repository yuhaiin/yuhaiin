//go:build linux

// Package dataplane implements the userspace VPN data path: a TUN device plus
// the ESP encapsulation pump that moves IP packets between the tunnel and the
// network.
package dataplane

import (
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux TUN/TAP ioctl constants (from <linux/if_tun.h> and <linux/if.h>).
const (
	cIFF_TUN         = 0x0001
	cIFF_TAP         = 0x0002
	cIFF_NO_PI       = 0x1000
	cIFF_VNET_HDR    = 0x4000
	cTUNSETIFF       = 0x400454ca
	cTUNSETOFFLOAD   = 0x400454d0
	cTUNSETVNETHDRSZ = 0x400454d8
	cIFNAMSIZ        = 16
	cTUN_F_CSUM      = 0x01
	cTUN_F_TSO4      = 0x02
)

// ifReq mirrors struct ifreq for the TUNSETIFF ioctl.
type ifReq struct {
	Name  [cIFNAMSIZ]byte
	Flags uint16
	_     [22]byte
}

// TUN is an open TUN network device operating in IFF_NO_PI mode, so reads and
// writes are bare IP packets with no 4-byte packet-info prefix.
//
// The device is held as a raw file descriptor and read/written with direct
// syscalls rather than an *os.File. A TUN fd registered with Go's runtime
// netpoller returns "not pollable" from a blocking Read on an idle interface
// (the poller cannot deliver readiness for the character device), which would
// kill the data-path read loop. So the poller is bypassed and readiness is
// waited for here:
//
//	Read: read(2) ──packet──▶ return
//	        │
//	     EAGAIN
//	        │
//	        ▼
//	     poll(2) on { tun: POLLIN, wake: POLLIN } ──┬── tun ready ─▶ read again
//	                                               └── wake ──────▶ ErrClosed
//
// The wake fd is why this shape exists. Held as a *blocking* fd — which is what
// this was until it caused a real deadlock — a parked read(2) cannot be
// interrupted: close(2) on Linux does not wake a thread already blocked reading
// that fd, so a protocol whose Close waits for its packet pump did not return
// until a packet happened to arrive, which on an idle tunnel may be never. That
// is invisible to `veepin serve <proto>`, which calls Close and exits, and fatal
// to anything that keeps running afterwards and holds a lock while it waits.
//
// The fast path is unchanged in syscall count: a device with a packet ready
// returns it from the first read(2) and never polls. Only an idle device pays
// the extra poll, and an idle device has no packet to slow down.
type TUN struct {
	virtual VirtualPacketIO
	fd      int
	name    string
	// vnet is true when the device was opened with IFF_VNET_HDR: every read
	// carries a 10-byte virtio-net header (and may be a GSO super-frame), and
	// every write must carry one. Only the pump's vnet-aware loop drives a TUN
	// in this mode.
	vnet bool

	// wake is an eventfd Close latches to interrupt a parked poll. It is
	// written once and never drained, so it stays readable: every later poll
	// returns immediately rather than racing to observe a one-shot signal.
	wake int

	// closed is the latch itself, readable without mu so a woken poll can tell
	// why it woke without waiting for Close to finish.
	closed atomic.Bool

	// mu guards the validity of fd and wake, not access to the device: Read and
	// Write hold it for reading across their syscalls, Close takes it
	// exclusively before closing either fd. Without it a reader between poll and
	// read(2) could issue that read against a descriptor number the kernel had
	// already recycled into some unrelated file — the quiet, occasional variety
	// of use-after-free that a data path should not have.
	//
	// Close signals wake *before* taking mu, which is what keeps this from
	// being the deadlock it replaces; see Close.
	mu sync.RWMutex
}

// newTUN wraps a freshly opened device fd: non-blocking, so a read on an idle
// interface returns EAGAIN and reaches the poll above instead of parking
// uninterruptibly in the kernel, plus the eventfd Close latches to wake it.
func newTUN(fd int, name string, vnet bool) (*TUN, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("dataplane: set TUN non-blocking: %w", err)
	}
	wake, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("dataplane: eventfd: %w", err)
	}
	return &TUN{fd: fd, name: name, vnet: vnet, wake: wake}, nil
}

// OpenTUN opens /dev/net/tun and configures a TUN interface. If name is empty
// the kernel picks one (tunN). Requires CAP_NET_ADMIN (run as root, or grant
// the binary the capability with: sudo setcap cap_net_admin+ep ./ikev2d).
func OpenTUN(name string) (*TUN, error) {
	if v, ok := consumeVirtualTUN(name); ok {
		return &TUN{name: name, virtual: v}, nil
	}
	// A raw syscall.Open fd is never handed to the netpoller; newTUN below makes
	// it non-blocking. O_CLOEXEC keeps it out of the children the server shells
	// out to (internal/hostnet runs ip and iptables), where an inherited copy
	// would hold the device open past our own Close.
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("dataplane: open /dev/net/tun: %w (need CAP_NET_ADMIN)", err)
	}

	var req ifReq
	copy(req.Name[:], name)
	req.Flags = cIFF_TUN | cIFF_NO_PI

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(cTUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("dataplane: TUNSETIFF: %v (need CAP_NET_ADMIN)", errno)
	}

	// The kernel writes back the assigned name.
	assigned := string(req.Name[:])
	if i := indexZero(req.Name[:]); i >= 0 {
		assigned = string(req.Name[:i])
	}

	return newTUN(fd, assigned, false)
}

// OpenTAP opens /dev/net/tun in TAP (Ethernet) mode. It reads and writes raw
// Ethernet frames (no packet-info header). Requires CAP_NET_ADMIN.
func OpenTAP(name string) (*TUN, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("dataplane: open /dev/net/tun: %w (need CAP_NET_ADMIN)", err)
	}

	var req ifReq
	copy(req.Name[:], name)
	req.Flags = cIFF_TAP | cIFF_NO_PI

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(cTUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("dataplane: TAP TUNSETIFF: %v (need CAP_NET_ADMIN)", errno)
	}

	assigned := string(req.Name[:])
	if i := indexZero(req.Name[:]); i >= 0 {
		assigned = string(req.Name[:i])
	}

	return newTUN(fd, assigned, false)
}

// OpenTUNGSO opens a TUN like OpenTUN, but negotiates the virtio-net header
// path (IFF_VNET_HDR) with TCP segmentation offload (TUN_F_CSUM|TUN_F_TSO4):
// the kernel's local stack may then hand one read a TCP super-frame of up to
// 64 KB in place of dozens of MTU-sized packets, which the pump cuts into
// wire-sized segments itself (offload_linux.go) and flushes with one batched
// send.
//
// A kernel that refuses any of the ioctls gets the plain device instead —
// same contract as OpenTUN, and GSO reports which case is in effect. Only
// dataplane.Pump knows how to drive a GSO device; a protocol with its own TUN
// loop must keep OpenTUN.
func OpenTUNGSO(name string) (*TUN, error) {
	if v, ok := consumeVirtualTUN(name); ok {
		return &TUN{name: name, virtual: v}, nil
	}
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("dataplane: open /dev/net/tun: %w (need CAP_NET_ADMIN)", err)
	}

	var req ifReq
	copy(req.Name[:], name)
	req.Flags = cIFF_TUN | cIFF_NO_PI | cIFF_VNET_HDR

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(cTUNSETIFF), uintptr(unsafe.Pointer(&req))); errno != 0 {
		// No vnet-header support at all: fall back to the plain device.
		_ = syscall.Close(fd)
		return OpenTUN(name)
	}

	vnetHdrSz := int32(virtioNetHdrLen)
	_, _, e1 := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(cTUNSETVNETHDRSZ), uintptr(unsafe.Pointer(&vnetHdrSz)))
	offloads := uintptr(cTUN_F_CSUM | cTUN_F_TSO4)
	_, _, e2 := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(cTUNSETOFFLOAD), offloads)
	if e1 != 0 || e2 != 0 {
		// Header without offloads would be all cost and no batching: reopen
		// plain rather than pay 10 bytes per packet for nothing.
		_ = syscall.Close(fd)
		return OpenTUN(name)
	}

	assigned := string(req.Name[:])
	if i := indexZero(req.Name[:]); i >= 0 {
		assigned = string(req.Name[:i])
	}
	return newTUN(fd, assigned, true)
}

// Name returns the interface name (e.g. "tun0").
func (t *TUN) Name() string {
	if t != nil && t.virtual != nil {
		return t.name
	}
	return t.name
}

// GSO reports whether the device is in virtio-net-header mode, in which case
// reads and writes carry the 10-byte header and reads may be GSO super-frames.
// Nil-safe, because tests hand pumps a nil *TUN they never run.
func (t *TUN) GSO() bool { return t != nil && t.virtual == nil && t.vnet }

// zeroVnetHdr is the header a plain (non-GSO, checksums-complete) packet
// written to a vnet TUN carries: all fields zero.
var zeroVnetHdr [virtioNetHdrLen]byte

// writeVnet writes one IP packet to a vnet-mode tunnel, prepending the zero
// virtio-net header with writev so the packet is not copied.
func (t *TUN) writeVnet(pkt []byte) (int, error) {
	return t.writeVnetGSO(zeroVnetHdr[:], pkt)
}

// writeVnetGSO writes one frame to a vnet-mode tunnel under the given
// virtio-net header — the GRO path's way of handing the kernel a coalesced
// super-frame with its GSO metadata. writev keeps the frame uncopied.
func (t *TUN) writeVnetGSO(hdr, pkt []byte) (int, error) {
	for {
		n, err := t.writev(hdr, pkt)
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN {
			if werr := t.wait(unix.POLLOUT); werr != nil {
				return 0, werr
			}
			continue
		}
		if n >= len(hdr) {
			n -= len(hdr)
		}
		return n, err
	}
}

// Read reads one IP packet from the tunnel into buf.
//
// EINTR (e.g. from Go's asynchronous goroutine preemption signal landing on the
// read) is retried transparently. EAGAIN — an idle device with nothing to give —
// parks in poll until there is a packet or Close latches the wake fd, and
// returns ErrClosed for the latter. See the type comment for why that indirection
// exists rather than a blocking read(2).
func (t *TUN) Read(buf []byte) (int, error) {
	if t.virtual != nil {
		return t.virtual.Read(buf)
	}
	for {
		n, err := t.read(buf)
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN {
			if werr := t.wait(unix.POLLIN); werr != nil {
				return 0, werr
			}
			continue
		}
		return n, err
	}
}

// Write writes one IP packet to the tunnel. A full device queue (EAGAIN, which
// a blocking fd would have absorbed by parking in the kernel) waits for room the
// same way Read waits for a packet, so a wedged interface cannot outlast Close
// here either.
func (t *TUN) Write(pkt []byte) (int, error) {
	if t.virtual != nil {
		return t.virtual.Write(pkt)
	}
	for {
		n, err := t.write(pkt)
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN {
			if werr := t.wait(unix.POLLOUT); werr != nil {
				return 0, werr
			}
			continue
		}
		return n, err
	}
}

// read, write and writev are the three device syscalls, each under the fd guard.
// Holding mu for reading is what makes the descriptor safe to name: Close cannot
// complete — and therefore cannot recycle the number out from under us — while
// any of them is in flight.
func (t *TUN) read(buf []byte) (int, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed.Load() {
		return 0, ErrClosed
	}
	return syscall.Read(t.fd, buf)
}

func (t *TUN) write(pkt []byte) (int, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed.Load() {
		return 0, ErrClosed
	}
	return syscall.Write(t.fd, pkt)
}

func (t *TUN) writev(hdr, pkt []byte) (int, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed.Load() {
		return 0, ErrClosed
	}
	return unix.Writev(t.fd, [][]byte{hdr, pkt})
}

// wait parks until the device is ready for events (POLLIN for Read, POLLOUT for
// Write) or Close latches the wake fd, which it reports as ErrClosed.
func (t *TUN) wait(events int16) error {
	// The poll set is built per call rather than kept on the TUN: Read and Write
	// run on different goroutines — the pump's single TUN reader, and whichever
	// tunnel is decapsulating inbound — so a shared one would need a lock of its
	// own. This is the idle path, where the device had nothing to give or no room
	// to take, so the cost lands where there is no packet to slow down.
	pfds := [2]unix.PollFd{
		{Fd: int32(t.fd), Events: events},
		{Fd: int32(t.wake), Events: unix.POLLIN},
	}
	for {
		if err := t.poll(pfds[:]); err != nil {
			if err == syscall.EINTR {
				continue
			}
			return err
		}
		// The wake fd is never drained, so once Close has latched it this is
		// true on every pass — no second reader can miss the signal.
		if t.closed.Load() || pfds[1].Revents != 0 {
			return ErrClosed
		}
		return nil
	}
}

// poll is the wait syscall under the same fd guard as the others.
func (t *TUN) poll(pfds []unix.PollFd) error {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed.Load() {
		return ErrClosed
	}
	_, err := unix.Poll(pfds, -1)
	return err
}

// Close closes the device and wakes anything parked on it. It is idempotent: a
// second call is a no-op rather than a close(2) of whatever file has since
// inherited the descriptor number.
func (t *TUN) Close() error {
	if t.virtual != nil {
		return t.virtual.Close()
	}
	if t.closed.Swap(true) {
		return nil
	}
	// Signal first, lock second, and the order is the whole point. A reader
	// parked in poll holds mu for reading, so taking mu here before waking it
	// would wait for exactly the read this is trying to interrupt — the deadlock
	// this mechanism exists to remove. Latching the eventfd unparks that poll,
	// which drops the read lock, which lets the exclusive lock below through.
	var one [8]byte
	binary.NativeEndian.PutUint64(one[:], 1)
	_, _ = unix.Write(t.wake, one[:])

	t.mu.Lock()
	defer t.mu.Unlock()
	err := syscall.Close(t.fd)
	if werr := syscall.Close(t.wake); err == nil {
		err = werr
	}
	return err
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

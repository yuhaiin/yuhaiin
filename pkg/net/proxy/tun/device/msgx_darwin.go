//go:build darwin && !ios

package device

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const maxUTUNBatch = 128

// XNU bsd/sys/socket_private.h, struct msghdr_x, LP64 on both arm64 and
// amd64. Keep actual pointers here, not uintptrs: the GC must see the buffers.
// Each header describes ONE datagram. Datalen is output only; zero on sends.
type msgHdrX struct {
	Name       unsafe.Pointer
	Namelen    uint32
	_          [4]byte
	Iov        *unix.Iovec
	Iovlen     int32
	_          [4]byte
	Control    unsafe.Pointer
	Controllen uint32
	Flags      int32
	Datalen    uint64
}

var (
	_ [56]byte = [unsafe.Sizeof(msgHdrX{})]byte{}
	_ [16]byte = [unsafe.Sizeof(unix.Iovec{})]byte{}
	_ [16]byte = [unsafe.Offsetof(msgHdrX{}.Iov)]byte{}
	_ [48]byte = [unsafe.Offsetof(msgHdrX{}.Datalen)]byte{}
)

// Verified against XNU bsd/kern/syscalls.master (480/481), and x/sys's
// SYS_RECVMSG_X/SYS_SENDMSG_X on BOTH Darwin architectures. Use Go's trap
// implementation: it supplies the amd64 Unix syscall class (0x2000000), or
// arm64 R16/SVC convention, and enters/exits the runtime's syscall state.
// libSystem exposes SPI wrappers on some releases, but a dynamic import would
// make a missing symbol a loader failure before we could fall back.
const (
	darwinRecvmsgX = 480
	darwinSendmsgX = 481
)

type msgxCounters struct {
	calls       atomic.Uint64
	packets     atomic.Uint64
	again       atomic.Uint64
	interrupted atomic.Uint64
	errors      atomic.Uint64
}

type msgxTrap func(uintptr, []msgHdrX, bool) (int, syscall.Errno)

// One instance per direction and device, protected by that direction's lock.
// Allocate once on the heap; never move or copy it once pointers are installed.
// The stored callback avoids allocating a closure on every RawConn operation.
type msgxIO struct {
	hdrs  [maxUTUNBatch]msgHdrX
	iovs  [maxUTUNBatch]unix.Iovec
	ready func(uintptr) bool
	trap  msgxTrap
	stats msgxCounters
	send  bool
	count int
	n     int
	errno syscall.Errno
}

func newMsgxIO(send bool) *msgxIO {
	m := &msgxIO{send: send, trap: msgxSyscall}
	m.ready = m.poll
	return m
}

func msgxSyscall(fd uintptr, hdrs []msgHdrX, send bool) (int, syscall.Errno) {
	number := uintptr(darwinRecvmsgX)
	if send {
		number = darwinSendmsgX
	}
	//nolint:staticcheck // Darwin SPI has no x/sys wrapper; see ABI notes above.
	r, _, errno := syscall.Syscall6(number, fd, uintptr(unsafe.Pointer(unsafe.SliceData(hdrs))), uintptr(len(hdrs)), unix.MSG_DONTWAIT, 0, 0)
	runtime.KeepAlive(hdrs)
	if errno != 0 {
		return 0, errno
	}
	if r > uintptr(len(hdrs)) {
		return 0, syscall.EIO
	}
	return int(r), 0
}

func (m *msgxIO) poll(fd uintptr) bool {
	for {
		m.stats.calls.Add(1)
		m.n, m.errno = m.trap(fd, m.hdrs[:m.count], m.send)
		// A positive prefix must never be replayed, including in fault-injection
		// tests. Real XNU reports a short count with errno=0 for normal pressure.
		if m.n > 0 {
			m.stats.packets.Add(uint64(m.n))
			return true
		}
		switch m.errno {
		case syscall.EINTR:
			m.stats.interrupted.Add(1)
			continue
		case syscall.EAGAIN:
			m.stats.again.Add(1)
			return false // park on Go's poller; Close/deadlines interrupt this wait
		case 0:
			m.errno = syscall.EIO // no progress must not spin forever
		}
		m.stats.errors.Add(1)
		return true
	}
}

func (m *msgxIO) transfer(rc syscall.RawConn, bufs [][]byte) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	if len(bufs) > maxUTUNBatch {
		return 0, syscall.EINVAL
	}
	for _, b := range bufs {
		if len(b) == 0 {
			return 0, io.ErrShortBuffer
		}
	}
	m.count, m.n, m.errno = len(bufs), 0, 0
	for i, b := range bufs {
		m.iovs[i] = unix.Iovec{Base: unsafe.SliceData(b), Len: uint64(len(b))}
		m.hdrs[i] = msgHdrX{Iov: &m.iovs[i], Iovlen: 1}
	}
	var err error
	if m.send {
		err = rc.Write(m.ready)
	} else {
		err = rc.Read(m.ready)
	}
	// RawConn holds the descriptor's reference across the callback and poll wait.
	// The kernel borrows all storage synchronously. No uintptr is retained.
	runtime.KeepAlive(bufs)
	runtime.KeepAlive(m)
	for i := range bufs {
		m.iovs[i].Base = nil
		m.hdrs[i].Iov = nil
	}
	if m.n < 0 || m.n > len(bufs) {
		return 0, syscall.EIO
	}
	if err != nil {
		return m.n, err
	}
	if m.errno != 0 {
		return m.n, m.errno
	}
	return m.n, nil
}

var msgxAvailability struct {
	sync.Mutex
	passed bool
}

func msgxAvailable() error {
	if os.Getenv("APP_SANDBOX_CONTAINER_ID") != "" {
		return errors.New("app sandbox: Darwin SPI disabled")
	}
	msgxAvailability.Lock()
	defer msgxAvailability.Unlock()
	if msgxAvailability.passed {
		return nil
	}
	err := msgxSmokeTest()
	// Cache success only. Temporary loopback pressure or a smoke-test timeout
	// must not mark SPI permanently unsupported for subsequently created TUNs.
	msgxAvailability.passed = err == nil
	return err
}

// A bounded real-kernel ABI test, NOT a utun performance test. Two connected
// loopback datagrams verify lengths, boundaries, and both actual syscalls.
func msgxSmokeTest() error {
	rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer rx.Close()
	tx, err := net.DialUDP("udp4", nil, rx.LocalAddr().(*net.UDPAddr))
	if err != nil {
		return err
	}
	defer tx.Close()
	deadline := time.Now().Add(time.Second)
	if err := rx.SetDeadline(deadline); err != nil {
		return err
	}
	if err := tx.SetDeadline(deadline); err != nil {
		return err
	}
	rrc, err := rx.SyscallConn()
	if err != nil {
		return err
	}
	trc, err := tx.SyscallConn()
	if err != nil {
		return err
	}
	want := [][]byte{{0, 0, 0, 2, 0x45, 1}, {0, 0, 0, 30, 0x60, 2, 3}}
	sender, receiver := newMsgxIO(true), newMsgxIO(false)
	for sent := 0; sent < len(want); {
		n, err := sender.transfer(trc, want[sent:])
		if err != nil {
			return fmt.Errorf("sendmsg_x smoke: %w", err)
		}
		sent += n
	}
	got := [][]byte{make([]byte, 64), make([]byte, 64)}
	for received := 0; received < len(want); {
		n, err := receiver.transfer(rrc, got[received:])
		if err != nil {
			return fmt.Errorf("recvmsg_x smoke: %w", err)
		}
		for i := range n {
			h := receiver.hdrs[i]
			if h.Datalen != uint64(len(want[received+i])) || h.Flags != 0 || !bytes.Equal(got[received+i][:h.Datalen], want[received+i]) {
				return errors.New("msgx smoke: datagram/ABI mismatch")
			}
		}
		received += n
	}
	return nil
}

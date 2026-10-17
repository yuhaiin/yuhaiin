//go:build darwin && !ios

package device

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// UDP is only an unprivileged ABI/adapter fixture, never evidence of utun speed.
type socketTun struct {
	file *os.File
	mtu  int
}

func (s *socketTun) Read(b [][]byte, sizes []int) (int, error) {
	n, e := s.file.Read(b[0])
	if n < 4 {
		return 0, e
	}
	sizes[0] = n - 4
	return 1, e
}
func (s *socketTun) Write(b [][]byte) (int, error) {
	for i, p := range b {
		if _, e := s.file.Write(p); e != nil {
			return i, e
		}
	}
	return len(b), nil
}
func (s *socketTun) Close() error   { return s.file.Close() }
func (*socketTun) BatchSize() int   { return 1 }
func (*socketTun) Offset() int      { return 4 }
func (s *socketTun) MTU() int       { return s.mtu }
func (*socketTun) GSOEnabled() bool { return false }

func udpSocketPair(t testing.TB) (*os.File, *os.File) {
	t.Helper()
	var files [2]*os.File
	for i := range files {
		fd, e := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
		if e != nil {
			t.Fatal(e)
		}
		unix.CloseOnExec(fd)
		if e = unix.SetNonblock(fd, true); e != nil {
			_ = unix.Close(fd)
			t.Fatal(e)
		}
		files[i] = os.NewFile(uintptr(fd), "msgx-test")
		t.Cleanup(func() { _ = files[i].Close() })
		if e = unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); e != nil {
			t.Fatal(e)
		}
		for _, opt := range []int{unix.SO_RCVBUF, unix.SO_SNDBUF} {
			if e = unix.SetsockoptInt(fd, unix.SOL_SOCKET, opt, 2<<20); e != nil {
				t.Fatal(e)
			}
		}
	}
	for i := range files {
		addr, e := unix.Getsockname(int(files[1-i].Fd()))
		if e != nil {
			t.Fatal(e)
		}
		if e = unix.Connect(int(files[i].Fd()), addr); e != nil {
			t.Fatal(e)
		}
		if e = files[i].SetDeadline(time.Now().Add(5 * time.Second)); e != nil {
			t.Fatal(e)
		}
	}
	return files[0], files[1]
}

func frames(n, size int) [][]byte {
	b := make([][]byte, n)
	for i := range b {
		b[i] = bytes.Repeat([]byte{byte(i)}, size+4)
		af, version := uint32(unix.AF_INET), byte(0x45)
		if i%2 != 0 && size >= 40 {
			af, version = unix.AF_INET6, 0x60
		}
		binary.BigEndian.PutUint32(b[i][:4], af)
		b[i][4] = version
		if af == unix.AF_INET && size >= 20 {
			binary.BigEndian.PutUint16(b[i][6:8], uint16(size))
		}
		if af == unix.AF_INET6 {
			binary.BigEndian.PutUint16(b[i][8:10], uint16(size-40))
		}
	}
	return b
}
func newTestBatch(t testing.TB, n int) (*utunBatch, *os.File) {
	t.Helper()
	f, peer := udpSocketPair(t)
	rc, e := f.SyscallConn()
	if e != nil {
		t.Fatal(e)
	}
	d := newUTUNBatch(&socketTun{f, 1500}, rc, n, socketSendBudget(t, rc))
	t.Cleanup(func() { _ = d.Close() })
	return d, peer
}

func TestMsgxABI(t *testing.T) {
	h := msgHdrX{}
	got := []uintptr{unsafe.Sizeof(h), unsafe.Alignof(h), unsafe.Offsetof(h.Name), unsafe.Offsetof(h.Namelen), unsafe.Offsetof(h.Iov), unsafe.Offsetof(h.Iovlen), unsafe.Offsetof(h.Control), unsafe.Offsetof(h.Controllen), unsafe.Offsetof(h.Flags), unsafe.Offsetof(h.Datalen), unsafe.Sizeof(unix.Iovec{}), unsafe.Alignof(unix.Iovec{})}
	want := []uintptr{56, 8, 0, 8, 16, 24, 32, 40, 44, 48, 16, 8}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ABI field %d = %d, want %d", i, got[i], want[i])
		}
	}
	// These deprecated constants are assertions against x/sys, not our dispatch.
	//nolint:staticcheck // Verify both architecture tables when cross-compiling.
	if darwinRecvmsgX != unix.SYS_RECVMSG_X || darwinSendmsgX != unix.SYS_SENDMSG_X {
		t.Fatal("syscall table changed")
	}
	if err := msgxSmokeTest(); err != nil {
		t.Fatalf("real syscall ABI smoke: %v", err)
	}
}

func TestUTUNBatchDatagrams(t *testing.T) {
	for _, n := range []int{1, 16, 32, 64, 128} {
		for _, size := range []int{20, 40, 64, 512, 1400, 1500, 9000} {
			t.Run(fmt.Sprintf("%d/%d", n, size), func(t *testing.T) {
				d, peer := newTestBatch(t, n)
				sent := frames(n, size)
				if got, e := d.Write(sent); got != n || e != nil {
					t.Fatalf("write %d: %v", got, e)
				}
				// Read independently to prove one message per IP frame, including order.
				buf := make([]byte, size+5)
				for i := range sent {
					got, e := peer.Read(buf)
					if e != nil || !bytes.Equal(buf[:got], sent[i]) {
						t.Fatalf("TX frame %d: len=%d err=%v", i, got, e)
					}
					if _, e = peer.Write(sent[i]); e != nil {
						t.Fatal(e)
					}
				}
				received := frames(n, size)
				for _, b := range received {
					clear(b)
				}
				sizes := make([]int, n)
				for count := 0; count < n; {
					got, e := d.Read(received[count:], sizes[count:])
					if e != nil || got == 0 {
						t.Fatalf("read %d: %v", got, e)
					}
					count += got
				}
				for i := range sent {
					if sizes[i] != size || !bytes.Equal(received[i], sent[i]) {
						t.Fatalf("RX frame %d mismatch", i)
					}
				}
				for _, m := range []*msgxIO{d.rx, d.tx} {
					for i := range n {
						if m.iovs[i].Base != nil || m.hdrs[i].Iov != nil {
							t.Fatal("retained caller buffer")
						}
					}
				}
			})
		}
	}
}

// Deterministic RawConn: false means poll wait, not permanent unavailability.
type scriptedRawConn struct{ waits int }

func (*scriptedRawConn) Control(f func(uintptr)) error     { f(0); return nil }
func (r *scriptedRawConn) Read(f func(uintptr) bool) error { return r.Write(f) }
func (r *scriptedRawConn) Write(f func(uintptr) bool) error {
	for range 1000 {
		if f(0) {
			return nil
		}
		r.waits++
	}
	return errors.New("excessive retry")
}

func TestMsgxInterruptAndBackpressure(t *testing.T) {
	for _, send := range []bool{false, true} {
		m := newMsgxIO(send)
		rc := new(scriptedRawConn)
		calls := 0
		m.trap = func(_ uintptr, h []msgHdrX, _ bool) (int, syscall.Errno) {
			calls++
			switch calls {
			case 1:
				return 0, syscall.EINTR
			case 2, 3:
				return 0, syscall.EAGAIN
			}
			return len(h), 0
		}
		if n, e := m.transfer(rc, frames(16, 64)); n != 16 || e != nil || rc.waits != 2 {
			t.Fatalf("n=%d e=%v waits=%d", n, e, rc.waits)
		}
		if m.stats.calls.Load() != 4 || m.stats.interrupted.Load() != 1 || m.stats.again.Load() != 2 {
			t.Fatal("wrong syscall counters")
		}
	}
}

func TestUTUNBatchPartialWriteFallback(t *testing.T) {
	d, peer := newTestBatch(t, 16)
	sent := frames(32, 64)
	calls := 0
	d.tx.trap = func(fd uintptr, h []msgHdrX, send bool) (int, syscall.Errno) {
		calls++
		switch calls {
		case 1:
			return msgxSyscall(fd, h[:3], send)
		case 2:
			return 0, syscall.ENOSYS
		}
		t.Fatal("used msgx after fallback")
		return 0, syscall.EIO
	}
	if n, e := d.Write(sent); n != 32 || e != nil {
		t.Fatalf("write n=%d e=%v", n, e)
	}
	b := make([]byte, 128)
	for i, w := range sent {
		n, e := peer.Read(b)
		if e != nil || !bytes.Equal(b[:n], w) {
			t.Fatalf("prefix duplicated/reordered at %d: %v", i, e)
		}
	}
	if !d.disabled.Load() || d.BatchSize() != 16 || d.UTUNBatchStats().FallbackWrites != 1 {
		t.Fatal("fallback/capability changed")
	}
}

func TestUTUNBatchUnknownTXNeverReplayed(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENOSPC, syscall.EIO, syscall.EINVAL} {
		t.Run(errno.Error(), func(t *testing.T) {
			d, peer := newTestBatch(t, 16)
			sent := frames(16, 64)
			d.tx.trap = func(fd uintptr, h []msgHdrX, send bool) (int, syscall.Errno) {
				// Emulate XNU hiding a successfully accepted prefix on an unknown error.
				if _, e := msgxSyscall(fd, h[:3], send); e != 0 {
					t.Fatal(e)
				}
				return 0, errno
			}
			if n, e := d.Write(sent); n != 0 || !errors.Is(e, errno) {
				t.Fatalf("n=%d e=%v", n, e)
			}
			if !d.disabled.Load() || d.UTUNBatchStats().TXUncertain != 16 || d.UTUNBatchStats().FallbackWrites != 0 {
				t.Fatal("uncertain send replayed")
			}
			// A new, independent call uses the original native path.
			if n, e := d.Write(sent[15:]); n != 1 || e != nil {
				t.Fatal(n, e)
			}
			b := make([]byte, 128)
			for _, i := range []int{0, 1, 2, 15} {
				n, e := peer.Read(b)
				if e != nil || !bytes.Equal(b[:n], sent[i]) {
					t.Fatal("replayed or reordered", i, e)
				}
			}
		})
	}
}

func TestUTUNBatchENOBUFSKeepsBatching(t *testing.T) {
	d, _ := newTestBatch(t, 16)
	d.tx.trap = func(uintptr, []msgHdrX, bool) (int, syscall.Errno) { return 0, syscall.ENOBUFS }
	if n, e := d.Write(frames(16, 64)); n != 0 || !errors.Is(e, syscall.ENOBUFS) || d.disabled.Load() {
		t.Fatalf("n=%d e=%v disabled=%v", n, e, d.disabled.Load())
	}
}

func TestUTUNBatchReadFallback(t *testing.T) {
	d, peer := newTestBatch(t, 16)
	want := frames(1, 64)
	if _, e := peer.Write(want[0]); e != nil {
		t.Fatal(e)
	}
	d.rx.trap = func(uintptr, []msgHdrX, bool) (int, syscall.Errno) { return 0, syscall.ENOSYS }
	got := frames(16, 64)
	sizes := make([]int, 16)
	if n, e := d.Read(got, sizes); n != 1 || e != nil || !bytes.Equal(got[0], want[0]) {
		t.Fatal(n, e)
	}
	if !d.disabled.Load() || d.UTUNBatchStats().FallbackReads != 1 {
		t.Fatal("no fallback")
	}
}

func TestUTUNBatchTruncatedAndMalformedFrames(t *testing.T) {
	for _, bad := range []string{"trunc", "header", "family", "length"} {
		t.Run(bad, func(t *testing.T) {
			d, peer := newTestBatch(t, 16)
			want := frames(3, 64)
			switch bad {
			case "trunc":
				want[1] = append(want[1], make([]byte, 100)...)
				binary.BigEndian.PutUint16(want[1][8:10], 124)
			case "header":
				want[1] = want[1][:3]
			case "family":
				want[1][3] = 99
			case "length":
				want[1] = want[1][:4]
			}
			for _, b := range want {
				if _, e := peer.Write(b); e != nil {
					t.Fatal(e)
				}
			}
			got := frames(16, 64)
			sizes := make([]int, 16)
			for d.UTUNBatchStats().RXDropped == 0 {
				n, e := d.Read(got, sizes)
				if e != nil && !errors.Is(e, syscall.ENOBUFS) {
					t.Fatal(e)
				}
				for i := range n {
					if !completeUTUNFrame(got[i][:sizes[i]+4]) {
						t.Fatal("delivered malformed packet")
					}
				}
			}
			// XNU can consume the entire list when a slot truncates. Never assert
			// that the not-yet-copied tail remains queued; explicitly count drops.
			if d.UTUNBatchStats().RXDropped == 0 {
				t.Fatal("drop not counted")
			}
		})
	}
}

func TestUTUNBatchCloseInterruptsReadAndWrite(t *testing.T) {
	for _, send := range []bool{false, true} {
		t.Run(fmt.Sprint(send), func(t *testing.T) {
			d, _ := newTestBatch(t, 16)
			entered := make(chan struct{})
			once := sync.Once{}
			m := d.rx
			if send {
				m = d.tx
			}
			m.trap = func(uintptr, []msgHdrX, bool) (int, syscall.Errno) {
				once.Do(func() { close(entered) })
				return 0, syscall.EAGAIN
			}
			done := make(chan error, 1)
			go func() {
				if send {
					_, e := d.Write(frames(16, 64))
					done <- e
				} else {
					_, e := d.Read(frames(16, 64), make([]int, 16))
					done <- e
				}
			}()
			<-entered
			// For a writable UDP socket the synthetic EAGAIN can wake repeatedly;
			// fd close must still interrupt RawConn, without taking the I/O locks.
			if e := d.Close(); e != nil {
				t.Fatal(e)
			}
			select {
			case e := <-done:
				if !errors.Is(e, os.ErrClosed) {
					t.Fatal(e)
				}
			case <-time.After(time.Second):
				t.Fatal("Close left I/O blocked")
			}
			if e := d.Close(); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestUTUNBatchValidation(t *testing.T) {
	d, _ := newTestBatch(t, 16)
	for _, b := range [][][]byte{{nil}, {{1}}, {make([]byte, 4)}} {
		if n, e := d.Write(b); n != 0 || !errors.Is(e, io.ErrShortBuffer) {
			t.Fatal(n, e)
		}
	}
	if n, e := d.Write([][]byte{make([]byte, 5)}); n != 0 || !errors.Is(e, syscall.EAFNOSUPPORT) {
		t.Fatal(n, e)
	}
	if n, e := d.Read(nil, nil); n != 0 || !errors.Is(e, io.ErrShortBuffer) {
		t.Fatal(n, e)
	}
	if d.tx.stats.calls.Load() != 0 {
		t.Fatal("invalid buffers reached kernel")
	}
}

func TestUTUNBatchOptions(t *testing.T) {
	t.Setenv("YUHAIIN_EXPERIMENTAL_UTUN_PENDING", "")
	for _, v := range []string{"", "0", "1", "16", "32", "64", "128", "true", "-1", "256"} {
		t.Setenv("YUHAIIN_EXPERIMENTAL_UTUN_BATCH", v)
		o, e := readUTUNBatchOptions()
		valid := v == "" || v == "0" || v == "1" || v == "16" || v == "32" || v == "64" || v == "128"
		if (e == nil) != valid {
			t.Fatalf("%q: %v", v, e)
		}
		if v == "" && o.batch != 0 {
			t.Fatal("enabled by default")
		}
	}
	t.Setenv("YUHAIIN_EXPERIMENTAL_UTUN_BATCH", "32")
	t.Setenv("YUHAIIN_EXPERIMENTAL_UTUN_PENDING", "128")
	if o, e := readUTUNBatchOptions(); e != nil || o.batch != 32 || o.pending != 128 {
		t.Fatal(o, e)
	}
	t.Setenv("YUHAIIN_EXPERIMENTAL_UTUN_PENDING", "256")
	if _, e := readUTUNBatchOptions(); e == nil {
		t.Fatal("invalid queue accepted")
	}
	for _, v := range []struct{ rcv, mtu, request, want int }{{512 << 10, 1500, 128, 128}, {512 << 10, 9000, 128, 50}, {512 << 10, 65575, 128, 6}, {1, 1500, 128, 1}, {-1, 1500, 16, 1}} {
		if got := utunPendingLimit(v.rcv, v.mtu, v.request); got != v.want {
			t.Fatalf("%+v got=%d", v, got)
		}
	}
}

func TestUTUNQueueSafetyGate(t *testing.T) {
	for _, scenario := range []string{"legacy", "netif", "unknown-mode", "blocking", "rcvbuf-error", "set-error", "readback-error"} {
		t.Run(scenario, func(t *testing.T) {
			pending, sets, reads := 1, 0, 0
			ops := utunSocketOps{
				get: func(_ int, level, opt int) (int, error) {
					if level == unix.SOL_SOCKET && opt == unix.SO_RCVBUF {
						if scenario == "rcvbuf-error" {
							return 0, syscall.EIO
						}
						return 512 << 10, nil
					}
					switch opt {
					case utunNetifOption:
						if scenario == "netif" {
							return 1, nil
						}
						if scenario == "unknown-mode" {
							return 0, syscall.ENOPROTOOPT
						}
						return 0, nil
					case utunMaxPendingOption:
						reads++
						if scenario == "readback-error" && reads == 2 {
							return 0, syscall.EIO
						}
						return pending, nil
					}
					t.Fatal("unknown socket option", level, opt)
					return 0, syscall.EINVAL
				},
				set: func(_ int, level, opt, value int) error {
					sets++
					if level != utunControlLevel || opt != 16 {
						t.Fatal("wrong option")
					}
					if scenario == "set-error" {
						return syscall.ENOPROTOOPT
					}
					pending = value
					return nil
				},
				flags: func(uintptr, int, int) (int, error) {
					if scenario == "blocking" {
						return 0, nil
					}
					return unix.O_NONBLOCK, nil
				},
			}
			r, p, e := configureUTUNSocket(0, 9000, 128, ops)
			if scenario == "legacy" {
				if e != nil || r != 512<<10 || p != 50 {
					t.Fatal(r, p, e)
				}
			} else if e == nil {
				t.Fatal("unsafe socket accepted")
			}
			if scenario == "netif" || scenario == "unknown-mode" || scenario == "blocking" || scenario == "rcvbuf-error" {
				if sets != 0 {
					t.Fatal("changed unverified device")
				}
			}
			if scenario == "readback-error" && (sets != 2 || pending != 1) {
				t.Fatal("failed readback did not restore old queue")
			}
		})
	}
}

func TestUTUNBatchDefaultAndExternalFD(t *testing.T) {
	t.Setenv("YUHAIIN_EXPERIMENTAL_UTUN_BATCH", "")
	d := new(wgDevice)
	if experimentalUTUN(d, true) != d {
		t.Fatal("default path changed")
	}
	t.Setenv("YUHAIIN_EXPERIMENTAL_UTUN_BATCH", "32")
	if experimentalUTUN(d, false) != d {
		t.Fatal("external fd used SPI")
	}
}

func TestUTUNBatchConcurrentWritersKeepBurstsOrdered(t *testing.T) {
	d, peer := newTestBatch(t, 16)
	const writers, perWriter = 4, 32
	var wg sync.WaitGroup
	for writer := range writers {
		wg.Go(func() {
			bufs := frames(perWriter, 64)
			for _, b := range bufs {
				b[24] = byte(writer)
			}
			if n, e := d.Write(bufs); n != perWriter || e != nil {
				t.Error(n, e)
			}
		})
	}
	b := make([]byte, 128)
	groups := make(map[byte]bool)
	for range writers {
		var id byte
		for i := range perWriter {
			n, e := peer.Read(b)
			if e != nil || n != 68 {
				t.Fatal(n, e)
			}
			if i == 0 {
				id = b[24]
				if groups[id] {
					t.Fatal("interleaved burst", id)
				}
				groups[id] = true
			} else if b[24] != id {
				t.Fatal("concurrent Write calls interleaved")
			}
		}
	}
	wg.Wait()
}

func TestUTUNBatchReadLengthValidationWithoutTruncFlag(t *testing.T) {
	for _, n := range []int{1, 2} {
		d, _ := newTestBatch(t, 16)
		d.rx.trap = func(_ uintptr, h []msgHdrX, _ bool) (int, syscall.Errno) {
			data := frames(2, 1400)
			for i := range n {
				copy(unsafe.Slice(h[i].Iov.Base, int(h[i].Iov.Len)), data[i])
				h[i].Datalen = 64
				h[i].Flags = 0
			}
			return n, 0
		}
		if got, e := d.Read(frames(16, 64), make([]int, 16)); got != 0 || !errors.Is(e, syscall.ENOBUFS) {
			t.Fatal("delivered truncated IP", got, e)
		}
	}
}

func TestUTUNBatchLargeWriteUnderPressure(t *testing.T) {
	d, _ := newTestBatch(t, 128)
	rc := new(scriptedRawConn)
	d.rc = rc
	bufs := frames(1024, 64)
	for i, b := range bufs {
		binary.BigEndian.PutUint32(b[48:52], uint32(i))
	}
	calls, accepted := 0, 0
	d.tx.trap = func(_ uintptr, h []msgHdrX, _ bool) (int, syscall.Errno) {
		calls++
		if len(h) > 128 {
			t.Fatal("unbounded kernel batch")
		}
		if calls%3 == 1 {
			return 0, syscall.EAGAIN
		}
		n := max(1, len(h)/2)
		for _, hdr := range h[:n] {
			data := unsafe.Slice(hdr.Iov.Base, int(hdr.Iov.Len))
			seq := int(binary.BigEndian.Uint32(data[48:52]))
			if seq != accepted {
				t.Fatal("duplicate or reordered under pressure", seq, accepted)
			}
			accepted++
		}
		return n, 0
	}
	if n, e := d.Write(bufs); n != 1024 || e != nil || accepted != 1024 || rc.waits == 0 {
		t.Fatal(n, e, accepted, rc.waits)
	}
	if d.disabled.Load() || d.UTUNBatchStats().TXPackets != 1024 {
		t.Fatal("ordinary pressure disabled batching")
	}
}

func TestUTUNKernelReflectionChecksums(t *testing.T) {
	for _, v := range []int{4, 6} {
		b := frames(2, 64)[v/6]
		p := b[4:]
		udp := p[20:]
		if v == 4 {
			p[9] = 17
			clear(p[6:8])
			clear(p[10:12])
		} else {
			p[6] = 17
			udp = p[40:]
		}
		binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
		if !reflectKernelUDP(b) {
			t.Fatal("valid UDP not reflected")
		}
		if v == 4 {
			if ipChecksum(p[:20]) != 0 {
				t.Fatal("invalid reflected IPv4 checksum")
			}
		} else {
			pseudo := make([]byte, 40+len(udp))
			copy(pseudo, p[8:40])
			binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(udp)))
			pseudo[39] = 17
			copy(pseudo[40:], udp)
			if ipChecksum(pseudo) != 0 {
				t.Fatal("invalid reflected IPv6 UDP checksum")
			}
		}
	}
}

func TestUTUNBatchPartialProgressWithPressure(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EAGAIN, syscall.EINTR} {
		t.Run(errno.Error(), func(t *testing.T) {
			d, peer := newTestBatch(t, 16)
			calls := 0
			bufs := frames(16, 64)
			d.tx.trap = func(fd uintptr, h []msgHdrX, send bool) (int, syscall.Errno) {
				calls++
				if calls == 1 {
					n, e := msgxSyscall(fd, h[:3], send)
					if e != 0 {
						t.Fatal(e)
					}
					return n, errno
				}
				return msgxSyscall(fd, h, send)
			}
			if n, e := d.Write(bufs); n != 16 || e != nil || d.disabled.Load() {
				t.Fatal(n, e, d.disabled.Load())
			}
			b := make([]byte, 128)
			for i, w := range bufs {
				n, e := peer.Read(b)
				if e != nil || !bytes.Equal(b[:n], w) {
					t.Fatal("pressure replayed prefix", i, e)
				}
			}
		})
	}
}

func socketSendBudget(t testing.TB, rc syscall.RawConn) int {
	t.Helper()
	var n int
	var e error
	if err := rc.Control(func(fd uintptr) { n, e = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF) }); err != nil {
		t.Fatal(err)
	}
	if e != nil || n < 1 {
		t.Fatal(n, e)
	}
	return n
}
func TestUTUNBatchHonorsSendByteBudget(t *testing.T) {
	d, peer := newTestBatch(t, 128)
	d.sendBytes = 3 * 1404
	bufs := frames(16, 1400)
	calls := 0
	d.tx.trap = func(fd uintptr, h []msgHdrX, send bool) (int, syscall.Errno) {
		calls++
		var total uint64
		for _, x := range h {
			total += x.Iov.Len
		}
		if total > uint64(d.sendBytes) {
			t.Fatal("send vector exceeds byte budget", total)
		}
		return msgxSyscall(fd, h, send)
	}
	if n, e := d.Write(bufs); n != 16 || e != nil || calls != 6 {
		t.Fatal(n, e, calls)
	}
	b := make([]byte, 1404)
	for i, w := range bufs {
		n, e := peer.Read(b)
		if e != nil || !bytes.Equal(b[:n], w) {
			t.Fatal("byte-limited ordering/integrity", i, e)
		}
	}
}

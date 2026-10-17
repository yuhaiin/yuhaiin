//go:build darwin && !ios

package device

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"golang.org/x/sys/unix"
)

const (
	utunControlLevel     = 2  // SYSPROTO_CONTROL
	utunMaxPendingOption = 16 // UTUN_OPT_MAX_PENDING_PACKETS: option number, NOT depth
	utunNetifOption      = 20 // UTUN_OPT_ENABLE_NETIF
)

type utunBatchOptions struct{ batch, pending int }

func validUTUNBatch(n int) bool { return n == 1 || n == 16 || n == 32 || n == 64 || n == 128 }

func init() { configureDarwinTUN = experimentalUTUN }

func resolveUTUNBatchOptions(config DarwinConfig) (utunBatchOptions, error) {
	if !config.ExperimentalBatch {
		return utunBatchOptions{}, nil
	}
	n, p := config.BatchSize, config.PendingPackets
	if n == 0 {
		n = 32
	}
	if p == 0 {
		p = n
	}
	if !validUTUNBatch(n) || !validUTUNBatch(p) {
		return utunBatchOptions{}, fmt.Errorf("invalid Darwin batch/pending size %d/%d (want 1,16,32,64,128)", n, p)
	}
	return utunBatchOptions{batch: n, pending: p}, nil
}

func experimentalUTUN(original netlink.Tun, owned bool, config DarwinConfig) netlink.Tun {
	opt, err := resolveUTUNBatchOptions(config)
	if err != nil {
		log.Warn("utun batching disabled", "err", err)
		return original
	}
	if opt.batch == 0 {
		return original
	}
	d, ok := original.(*wgDevice)
	if !ok {
		return original
	}

	// Never change a borrowed fd's queue or assume a NetworkExtension fd is safe.
	if !owned {
		log.Warn("utun batching disabled for external fd")
		return d
	}
	if err := msgxAvailable(); err != nil {
		log.Warn("utun batching smoke test failed; using single packets", "err", err)
		return d
	}
	file := d.File()
	if file == nil {
		return d
	}
	rc, err := file.SyscallConn()
	if err != nil {
		log.Warn("utun batching unavailable", "err", err)
		return d
	}
	var rcvbuf, pending, sndbuf int
	var setupErr error
	err = rc.Control(func(fd uintptr) {
		sndbuf, setupErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
		if setupErr != nil {
			return
		}
		if sndbuf < 1 {
			setupErr = errors.New("invalid SO_SNDBUF")
			return
		}
		rcvbuf, pending, setupErr = configureUTUNBatch(int(fd), d.MTU(), opt.pending)
	})
	if err == nil {
		err = setupErr
	}
	if err != nil {
		log.Warn("utun batching setup failed; using single packets", "err", err)
		return d
	}
	b := newUTUNBatch(d, rc, opt.batch, sndbuf)
	log.Warn("experimental utun batching enabled (traditional utun only)", "batch", opt.batch, "pending_requested", opt.pending, "pending", pending, "so_rcvbuf", rcvbuf, "so_sndbuf", sndbuf)
	return b
}

// The byte budget and pending-packet limit are different. Leave 1/8 of the
// measured receive buffer free, rather than assuming the requested depth fits.
// Do not change global sysctls or enlarge socket buffers automatically.
func utunPendingLimit(rcvbuf, mtu, requested int) int {
	if mtu < 1 || mtu > 65575 || rcvbuf < 1 {
		return 1
	}
	return max(1, min(requested, (rcvbuf/8*7)/(mtu+4)))
}

func configureUTUNBatch(fd, mtu, requested int) (rcvbuf, pending int, err error) {
	return configureUTUNSocket(fd, mtu, requested, utunSocketOps{unix.GetsockoptInt, unix.SetsockoptInt, unix.FcntlInt})
}

type utunSocketOps struct {
	get   func(int, int, int) (int, error)
	set   func(int, int, int, int) error
	flags func(uintptr, int, int) (int, error)
}

func configureUTUNSocket(fd, mtu, requested int, ops utunSocketOps) (rcvbuf, pending int, err error) {
	// Fail closed if the kernel cannot positively identify a traditional utun.
	mode, err := ops.get(fd, utunControlLevel, utunNetifOption)
	if err != nil {
		return 0, 0, fmt.Errorf("cannot verify UTUN_OPT_ENABLE_NETIF: %w", err)
	}
	if mode != 0 {
		return 0, 0, errors.New("netif utun: sendmsg_x is unsafe (ENOSPC/mbuf leak)")
	}
	flags, err := ops.flags(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return 0, 0, err
	}
	if flags&unix.O_NONBLOCK == 0 {
		return 0, 0, errors.New("utun fd is not nonblocking")
	}
	rcvbuf, err = ops.get(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil {
		return 0, 0, err
	}
	old, err := ops.get(fd, utunControlLevel, utunMaxPendingOption)
	if err != nil {
		return 0, 0, err
	}
	pending = utunPendingLimit(rcvbuf, mtu, requested)
	if err = ops.set(fd, utunControlLevel, utunMaxPendingOption, pending); err != nil {
		return rcvbuf, 0, err
	}
	actual, err := ops.get(fd, utunControlLevel, utunMaxPendingOption)
	if err != nil || actual != pending {
		_ = ops.set(fd, utunControlLevel, utunMaxPendingOption, old)
		return rcvbuf, 0, errors.New("utun pending-packet readback failed")
	}
	return rcvbuf, actual, nil
}

// UTUNBatchStats is a live per-device snapshot. Successful batch averages are
// packets / (syscalls - EAGAIN - EINTR - errors); raw totals also expose pressure.
// Snapshot via interface{ UTUNBatchStats() UTUNBatchStats }; also logged on Close.
type UTUNBatchStats struct {
	Disabled                                              bool
	RXCalls, RXPackets, RXAgain, RXInterrupted, RXErrors  uint64
	TXCalls, TXPackets, TXAgain, TXInterrupted, TXErrors  uint64
	FallbackReads, FallbackWrites, RXDropped, TXUncertain uint64
}

type utunBatch struct {
	netlink.Tun
	rc                                                    syscall.RawConn
	batch                                                 int // immutable, even after fallback: readers already allocated buffers
	sendBytes                                             int // actual SO_SNDBUF, immutable
	nativeEventsDone                                      <-chan struct{}
	readMu, writeMu                                       sync.Mutex
	rx, tx                                                *msgxIO
	disabled                                              atomic.Bool
	closed                                                atomic.Bool
	fallbackReads, fallbackWrites, rxDropped, txUncertain atomic.Uint64
	closeOnce                                             sync.Once
	closeErr                                              error
}

func newUTUNBatch(d netlink.Tun, rc syscall.RawConn, batch, sendBytes int) *utunBatch {
	b := &utunBatch{Tun: d, rc: rc, batch: batch, sendBytes: sendBytes, rx: newMsgxIO(false), tx: newMsgxIO(true)}
	if native, ok := d.(*wgDevice); ok {
		b.nativeEventsDone = native.eventsDone
	}
	return b
}

func (d *utunBatch) BatchSize() int                 { return d.batch }
func (d *utunBatch) ExperimentalUTUNBatchSize() int { return d.batch }
func (d *utunBatch) UTUNBatchStats() UTUNBatchStats {
	return UTUNBatchStats{
		Disabled: d.disabled.Load(),
		RXCalls:  d.rx.stats.calls.Load(), RXPackets: d.rx.stats.packets.Load(), RXAgain: d.rx.stats.again.Load(), RXInterrupted: d.rx.stats.interrupted.Load(), RXErrors: d.rx.stats.errors.Load(),
		TXCalls: d.tx.stats.calls.Load(), TXPackets: d.tx.stats.packets.Load(), TXAgain: d.tx.stats.again.Load(), TXInterrupted: d.tx.stats.interrupted.Load(), TXErrors: d.tx.stats.errors.Load(),
		FallbackReads: d.fallbackReads.Load(), FallbackWrites: d.fallbackWrites.Load(), RXDropped: d.rxDropped.Load(), TXUncertain: d.txUncertain.Load(),
	}
}
func (d *utunBatch) disable(op string, err error) {
	if d.disabled.CompareAndSwap(false, true) {
		log.Warn("utun batching disabled for this device", "op", op, "err", err)
	}
}
func (d *utunBatch) Close() error {
	d.closeOnce.Do(func() {
		d.closed.Store(true)
		// Close first: do not wait behind a reader/writer parked on the poller.
		d.closeErr = d.Tun.Close()
		d.readMu.Lock()
		d.rx.ready = nil
		d.readMu.Unlock()
		d.writeMu.Lock()
		d.tx.ready = nil
		d.writeMu.Unlock()
		log.Info("experimental utun batching stopped", "stats", d.UTUNBatchStats())
	})
	return d.closeErr
}

func (d *utunBatch) Read(bufs [][]byte, sizes []int) (int, error) {
	d.readMu.Lock()
	defer d.readMu.Unlock()
	if d.closed.Load() {
		return 0, os.ErrClosed
	}
	if len(bufs) == 0 || len(sizes) < len(bufs) {
		return 0, io.ErrShortBuffer
	}
	bufs = bufs[:min(len(bufs), d.batch)]
	for _, b := range bufs {
		if len(b) < 5 {
			return 0, io.ErrShortBuffer
		}
	}
	if d.nativeEventsDone != nil && !d.disabled.Load() {
		select {
		case <-d.nativeEventsDone:
			// The native reader checks its private route-listener error queue.
			// Do not bypass that terminal error after the event stream ends.
			d.disable("native events", errors.New("utun event stream stopped"))
		default:
		}
	}
	if d.disabled.Load() {
		d.fallbackReads.Add(1)
		return d.Tun.Read(bufs, sizes)
	}
	n, err := d.rx.transfer(d.rc, bufs)
	if d.closed.Load() && n == 0 {
		return 0, os.ErrClosed
	}
	if err != nil {
		if n == 0 && (errors.Is(err, os.ErrClosed) || errors.Is(err, syscall.ENOBUFS)) {
			return 0, err
		}
		if !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) && !errors.Is(err, syscall.ENOBUFS) {
			d.disable("recvmsg_x", err)
		}
		if n == 0 {
			d.fallbackReads.Add(1)
			return d.Tun.Read(bufs, sizes)
		}
	}
	out := 0
	for i := range n {
		h := d.rx.hdrs[i]
		length := int(h.Datalen)
		valid := h.Flags&unix.MSG_TRUNC == 0 && length >= 5 && h.Datalen <= uint64(len(bufs[i]))
		if valid {
			valid = completeUTUNFrame(bufs[i][:length])
		}
		if !valid || length > len(bufs[out]) {
			d.rxDropped.Add(1)
			continue
		}
		if i != out {
			copy(bufs[out], bufs[i][:length])
		}
		sizes[out] = length - 4
		out++
	}
	if out != n {
		// Legacy tun2socket readers discard n when err != nil. Deliver valid
		// frames first; drops remain observable in RXDropped. With no valid
		// frame, return pressure so all callers keep the device alive.
		if out == 0 {
			return 0, syscall.ENOBUFS
		}
	}
	return out, nil
}

// Some XNU receive-list implementations fail to publish MSG_TRUNC in each
// msghdr_x. Also verify the IP length, so truncated packets cannot reach a stack.
// IPv6 jumbograms exceed this device's maximum packet size and are rejected.
func completeUTUNFrame(frame []byte) bool {
	if len(frame) < 5 {
		return false
	}
	p := frame[4:]
	switch binary.BigEndian.Uint32(frame[:4]) {
	case unix.AF_INET:
		return len(p) >= 20 && p[0]>>4 == 4 && int(p[0]&15)*4 >= 20 && int(p[0]&15)*4 <= len(p) && int(binary.BigEndian.Uint16(p[2:4])) == len(p)
	case unix.AF_INET6:
		return len(p) >= 40 && p[0]>>4 == 6 && int(binary.BigEndian.Uint16(p[4:6]))+40 == len(p)
	}
	return false
}

func (d *utunBatch) Write(bufs [][]byte) (int, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	if d.closed.Load() {
		return 0, os.ErrClosed
	}
	// Validate before any send: a validation error must not claim unsent packets.
	maxFrame := 1
	for _, b := range bufs {
		if len(b) < 5 {
			return 0, io.ErrShortBuffer
		}
		var af uint32
		switch b[4] >> 4 {
		case 4:
			af = unix.AF_INET
		case 6:
			af = unix.AF_INET6
		default:
			return 0, syscall.EAFNOSUPPORT
		}
		binary.BigEndian.PutUint32(b[:4], af)
		maxFrame = max(maxFrame, len(b))
	}
	// XNU may reject a whole vector above the socket's send byte budget.
	// Largest-frame sizing is conservative for mixed lengths and needs no
	// second per-packet pass. A single oversized datagram keeps native errors.
	limit := max(1, min(d.batch, d.sendBytes/maxFrame))
	written := 0
	for written < len(bufs) {
		if d.disabled.Load() {
			d.fallbackWrites.Add(1)
			n, err := d.Tun.Write(bufs[written:])
			return written + n, err
		}
		end := min(written+limit, len(bufs))
		n, err := d.tx.transfer(d.rc, bufs[written:end])
		written += n
		if err != nil && d.closed.Load() {
			return written, os.ErrClosed
		}
		if err == nil {
			continue
		} // short successful send: retry only its suffix
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
			if n > 0 {
				continue
			}
			return written, err
		}
		if errors.Is(err, os.ErrClosed) || errors.Is(err, syscall.ENOBUFS) {
			return written, err
		}
		d.disable("sendmsg_x", err)
		// ENOSYS is raised before dispatch, so no packet in this call was sent.
		if errors.Is(err, syscall.ENOSYS) {
			continue
		}
		// XNU may hide an accepted prefix on unexpected errors (notably ENOSPC).
		// Do NOT replay that uncertain call through write(2). Future independent
		// calls use the native path. Surface the error, with only the known prefix.
		d.txUncertain.Add(uint64(end - written))
		return written, err
	}
	return written, nil
}

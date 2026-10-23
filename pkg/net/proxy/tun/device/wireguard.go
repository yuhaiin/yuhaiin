package device

import (
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	wun "github.com/tailscale/wireguard-go/tun"
)

type wgDevice struct {
	wun.Device
	offset int
	mtu    int
	gso    bool

	readMu  sync.Mutex
	slab    []byte
	packets []wun.ReadPacket

	closed     atomic.Bool
	closeOnce  sync.Once
	closeErr   error
	eventsDone <-chan struct{}
}

// NewDevice owns the device, including its event stream. Packet stack adapters
// do not consume link events; draining them keeps native listeners stoppable.
func NewDevice(device wun.Device, offset, mtu int, gsoEnabled bool) *wgDevice {
	wrwc := &wgDevice{
		Device: device,
		offset: offset,
		mtu:    mtu,
		gso:    gsoEnabled,
	}
	if events := device.Events(); events != nil {
		done := make(chan struct{})
		wrwc.eventsDone = done
		go func() {
			defer close(done)
			for range events {
			}
		}()
	}

	return wrwc
}

func (t *wgDevice) Offset() int      { return t.offset }
func (t *wgDevice) MTU() int         { return t.mtu }
func (t *wgDevice) GSOEnabled() bool { return t.gso }

// ReadPacketView is the single-packet native path (notably macOS utun). Its
// borrowed slab is consumed synchronously before the next read. Batch/GSO
// devices keep using Read, where the native engine owns segmentation semantics.
func (t *wgDevice) ReadPacketView() ([]byte, bool, error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()
	if t.closed.Load() {
		return nil, false, os.ErrClosed
	}
	if t.BatchSize() != 1 || t.gso {
		return nil, false, errors.New("native packet views require a plain single-packet device")
	}
	const size = 65575 + 2*wun.ReadPacketSpacing
	if len(t.slab) < size {
		t.slab = make([]byte, size)
	}
	if len(t.packets) == 0 {
		t.packets = make([]wun.ReadPacket, 1)
	}
	n, err := t.Device.Read(t.slab[:size], t.packets[:1])
	if errors.Is(err, wun.ErrTooManySegments) {
		err = errors.Join(err, syscall.ENOBUFS)
	}
	if n == 0 {
		return nil, false, err
	}
	p := t.packets[0]
	if n != 1 || p.Offset < 0 || p.Size < 1 || p.Offset > len(t.slab) || p.Size > len(t.slab)-p.Offset {
		return nil, false, io.ErrShortBuffer
	}
	return t.slab[p.Offset : p.Offset+p.Size], false, err
}
func (t *wgDevice) Read(bufs [][]byte, sizes []int) (n int, err error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()
	if t.closed.Load() {
		return 0, os.ErrClosed
	}

	if len(bufs) < t.BatchSize() || len(sizes) < len(bufs) {
		return 0, wun.ErrTooManySegments
	}

	// The native reader packs packets into one slab, with reserved space
	// around each packet. Keep the project's per-packet buffer interface.
	slabSize := wun.ReadPacketSpacing
	for _, buf := range bufs {
		if t.offset < 0 || len(buf) < t.offset {
			return 0, io.ErrShortBuffer
		}
		slabSize += len(buf) - t.offset + wun.ReadPacketSpacing
	}
	if len(t.slab) < slabSize {
		t.slab = make([]byte, slabSize)
	}
	if len(t.packets) < len(bufs) {
		t.packets = make([]wun.ReadPacket, len(bufs))
	}

	n, err = t.Device.Read(t.slab[:slabSize], t.packets[:len(bufs)])
	if errors.Is(err, wun.ErrTooManySegments) {
		// A packet that does not fit is dropped by the native reader. Report
		// buffer pressure so link readers keep the TUN alive for later packets.
		err = errors.Join(err, syscall.ENOBUFS)
	}
	for i, packet := range t.packets[:n] {
		if packet.Size > len(bufs[i])-t.offset {
			return i, errors.Join(err, io.ErrShortBuffer)
		}
		sizes[i] = copy(bufs[i][t.offset:], t.slab[packet.Offset:packet.Offset+packet.Size])
	}
	return n, err
}

func (t *wgDevice) Write(bufs [][]byte) (int, error) {
	if t.closed.Load() {
		return 0, os.ErrClosed
	}
	return t.Device.Write(bufs, t.offset)
}

func (t *wgDevice) Close() error {
	t.closeOnce.Do(func() {
		t.closed.Store(true)
		// Unblock a native Read before taking the lock that protects its slab.
		t.closeErr = t.Device.Close()
		t.readMu.Lock()
		t.slab, t.packets = nil, nil
		t.readMu.Unlock()
		if t.eventsDone != nil {
			<-t.eventsDone
		}
	})
	return t.closeErr
}

func (t *wgDevice) Tun() wun.Device { return t.Device }

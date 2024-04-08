package tun

import (
	"fmt"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"golang.zx2c4.com/wireguard/conn"
	wun "golang.zx2c4.com/wireguard/tun"
)

const (
	offset = 0
)

func OpenWriter(sc netlink.TunScheme, mtu int) (netlink.Writer, error) {
	var err error
	var device wun.Device
	switch sc.Scheme {
	case "tun":
		wd, err := wun.CreateTUN(sc.Name, mtu)
		if err != nil {
			return nil, fmt.Errorf("create tun failed: %w", err)
		}

		if wd.BatchSize() == conn.IdealBatchSize {
			wd = newWrapGsoDevice(wd)
			// gso enabled
		}
		device = wd
	case "fd":
		device, _, err = wun.CreateUnmonitoredTUNFromFD(sc.Fd)
	default:
		return nil, fmt.Errorf("invalid tun: %v", sc)
	}
	if err != nil {
		return nil, fmt.Errorf("create tun failed: %w", err)
	}

	return newWgReadWriteCloser(device), nil
}

type wrapGsoDevice struct {
	wun.Device

	w  sync.Mutex
	wb [][]byte
	ww [][]byte
}

func newWrapGsoDevice(device wun.Device) *wrapGsoDevice {

	w := &wrapGsoDevice{
		Device: device,
		wb:     make([][]byte, device.BatchSize()),
		ww:     make([][]byte, device.BatchSize()),
	}

	for i := range w.wb {
		w.wb[i] = make([]byte, 65536)
	}
	w.ww = w.ww[:0]

	return w
}

func (w *wrapGsoDevice) Write(bufs [][]byte, offset int) (int, error) {
	// https://github.com/WireGuard/wireguard-go/blob/12269c2761734b15625017d8565745096325392f/tun/offload_linux.go#L867
	//
	// virtioNetHdrLen = 10
	w.w.Lock()
	defer w.w.Unlock()

	for i := range bufs {
		n := copy(w.wb[i][10:], bufs[i])
		w.ww = append(w.ww, w.wb[i][:n+10])
	}

	n, err := w.Device.Write(w.ww, 10)

	w.ww = w.ww[:0]

	return n, err
}

func (w *wrapGsoDevice) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	// https://github.com/WireGuard/wireguard-go/blob/12269c2761734b15625017d8565745096325392f/tun/offload_linux.go#L867
	//
	// virtioNetHdrLen = 10
	n, err = w.Device.Read(bufs, sizes, 10)
	if err != nil {
		return
	}

	for x := range n {
		if sizes[x] < 10 {
			return n, fmt.Errorf("invalid packet size small than virtioHdr 10: %d", sizes[x])
		}

		copy(bufs[x], bufs[x][10:])
	}

	return
}

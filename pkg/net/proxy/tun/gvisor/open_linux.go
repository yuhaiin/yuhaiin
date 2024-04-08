package tun

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/tailscale/wireguard-go/conn"
	wun "github.com/tailscale/wireguard-go/tun"
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
	mtu int
}

func newWrapGsoDevice(device wun.Device) *wrapGsoDevice {
	mtu, _ := device.MTU()
	if mtu <= 0 {
		mtu = nat.MaxSegmentSize
	}
	w := &wrapGsoDevice{
		Device: device,
		mtu:    mtu,
	}

	return w
}

func (w *wrapGsoDevice) Write(bufs [][]byte, offset int) (int, error) {
	// https://github.com/WireGuard/wireguard-go/blob/12269c2761734b15625017d8565745096325392f/tun/offload_linux.go#L867
	//
	// virtioNetHdrLen = 10
	buffers := getBuffer(len(bufs), w.mtu+offset+10)
	defer putBuffer(buffers)

	for i := range bufs {
		copy(buffers[i][10:], bufs[i])
	}

	return w.Device.Write(buffers, 10)
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

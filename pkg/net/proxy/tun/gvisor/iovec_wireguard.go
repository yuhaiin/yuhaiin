package tun

import (
	wun "github.com/tailscale/wireguard-go/tun"
)

type wgDevice struct {
	wun.Device
	offset int
	mtu    int
}

func NewDevice(device wun.Device, offset, mtu int) *wgDevice {
	wrwc := &wgDevice{
		Device: device,
		offset: offset,
		mtu:    mtu,
	}

	return wrwc
}

func (t *wgDevice) Offset() int { return t.offset }
func (t *wgDevice) MTU() int    { return t.mtu }
func (t *wgDevice) Read(bufs [][]byte, sizes []int) (n int, err error) {
	return t.Device.Read(bufs, sizes, t.offset)
}

func (t *wgDevice) Write(bufs [][]byte) (int, error) {
	return t.Device.Write(bufs, t.offset)
}

func (t *wgDevice) Tun() wun.Device { return t.Device }

package tun

import (
	"fmt"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"golang.zx2c4.com/wireguard/conn"
	wun "golang.zx2c4.com/wireguard/tun"
)

type wgReadWriteCloser struct {
	nt wun.Device

	wmu    sync.Mutex
	rmu    sync.Mutex
	wbuf   [][]byte
	ww     [][]byte
	rbuf   [][]byte
	rsize  []int
	mtu    int
	prefix int
}

func newWgReadWriteCloser(device wun.Device) *wgReadWriteCloser {
	mtu, _ := device.MTU()
	if mtu <= 0 {
		mtu = nat.MaxSegmentSize
	}
	wrwc := &wgReadWriteCloser{
		nt:  device,
		mtu: mtu,

		wbuf:  make([][]byte, device.BatchSize()),
		ww:    make([][]byte, device.BatchSize()),
		rbuf:  make([][]byte, device.BatchSize()),
		rsize: make([]int, device.BatchSize()),
	}

	for i := range wrwc.rbuf {
		wrwc.rbuf[i] = make([]byte, offset+mtu+10)
		wrwc.wbuf[i] = make([]byte, offset+mtu+10)
	}
	wrwc.ww = wrwc.ww[:0]

	if device.BatchSize() == conn.IdealBatchSize {
		// https://github.com/WireGuard/wireguard-go/blob/12269c2761734b15625017d8565745096325392f/tun/offload_linux.go#L867
		//
		// virtioNetHdrLen = 10
		wrwc.prefix = 10
	}
	return wrwc
}

func (t *wgReadWriteCloser) Read(bufs [][]byte, sizes []int) (n int, err error) {
	t.rmu.Lock()
	defer t.rmu.Unlock()

	count, err := t.nt.Read(t.rbuf, t.rsize, offset)
	if err != nil {
		return 0, err
	}

	if count > len(bufs) {
		return 0, fmt.Errorf("buffer %d is smaller than recevied: %d", len(bufs), count)
	}

	for i := range bufs {
		copy(bufs[i], t.rbuf[i][offset:t.rsize[i]+offset])
		sizes[i] = t.rsize[i]
	}

	return count, err
}

func (t *wgReadWriteCloser) Write(bufs [][]byte) (int, error) {
	t.wmu.Lock()
	defer t.wmu.Unlock()

	if len(bufs) > len(t.wbuf) {
		return 0, fmt.Errorf("buffer %d is overflow, recevied: %d", len(t.wbuf), len(bufs))
	}

	for i := range bufs {
		n := copy(t.wbuf[i][offset:], bufs[i])
		t.ww = append(t.ww, t.wbuf[i][:n+offset])
	}

	_, err := t.nt.Write(t.ww, offset)
	if err != nil {
		return 0, err
	}

	t.ww = t.ww[:0]

	return len(bufs), nil
}

func (t *wgReadWriteCloser) Close() error       { return t.nt.Close() }
func (t *wgReadWriteCloser) Device() wun.Device { return t.nt }

func (t *wgReadWriteCloser) Prefix() int {
	return t.prefix
}

func (t *wgReadWriteCloser) BatchSize() int { return t.Device().BatchSize() }

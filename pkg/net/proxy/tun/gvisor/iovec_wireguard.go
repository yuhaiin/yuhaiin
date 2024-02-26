package tun

import (
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	wun "golang.zx2c4.com/wireguard/tun"
)

type wgReadWriteCloser struct {
	nt wun.Device

	wmu   sync.Mutex
	rmu   sync.Mutex
	wbuf  [][]byte
	rbuf  [][]byte
	rsize []int
	mtu   int
}

func newWgReadWriteCloser(device wun.Device) *wgReadWriteCloser {
	mtu, _ := device.MTU()
	if mtu <= 0 {
		mtu = nat.MaxSegmentSize
	}
	wrwc := &wgReadWriteCloser{
		nt:  device,
		mtu: mtu,

		wbuf:  make([][]byte, 1),
		rbuf:  make([][]byte, 1),
		rsize: make([]int, 1),
	}

	wrwc.wbuf[0] = make([]byte, offset+mtu)
	wrwc.rbuf[0] = make([]byte, offset+mtu)

	return wrwc
}

func (t *wgReadWriteCloser) Read(packet []byte) (int, error) {
	t.rmu.Lock()
	defer t.rmu.Unlock()

	_, err := t.nt.Read(t.rbuf, t.rsize, offset)

	n := copy(packet, t.rbuf[0][offset:t.rsize[0]])
	return n, err
}

func (t *wgReadWriteCloser) Write(packet []byte) (int, error) {
	t.wmu.Lock()
	defer t.wmu.Unlock()

	copy(t.wbuf[0][offset:], packet)

	_, err := t.nt.Write(t.wbuf, offset)
	if err != nil {
		return 0, err
	}
	return len(packet), nil
}

func (t *wgReadWriteCloser) Close() error       { return t.nt.Close() }
func (t *wgReadWriteCloser) Device() wun.Device { return t.nt }

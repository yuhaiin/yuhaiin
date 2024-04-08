package tun

import (
	"fmt"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	wun "golang.zx2c4.com/wireguard/tun"
)

type wgReadWriteCloser struct {
	nt wun.Device

	mtu int
}

func newWgReadWriteCloser(device wun.Device) *wgReadWriteCloser {
	mtu, _ := device.MTU()
	if mtu <= 0 {
		mtu = nat.MaxSegmentSize
	}
	wrwc := &wgReadWriteCloser{
		nt:  device,
		mtu: mtu,
	}

	return wrwc
}

func (t *wgReadWriteCloser) Read(bufs [][]byte, sizes []int) (n int, err error) {
	buffers := getBuffer(t.nt.BatchSize(), offset+t.mtu+10)
	defer putBuffer(buffers)
	size := buffPool(t.nt.BatchSize(), true).Get().([]int)
	defer buffPool(t.nt.BatchSize(), true).Put(size)

	count, err := t.nt.Read(buffers, size, offset)
	if err != nil {
		return 0, err
	}

	if count > len(bufs) {
		return 0, fmt.Errorf("buffer %d is smaller than recevied: %d", len(bufs), count)
	}

	for i := range bufs {
		copy(bufs[i], buffers[i][offset:size[i]+offset])
		sizes[i] = size[i]
	}

	return count, err
}

func (t *wgReadWriteCloser) Write(bufs [][]byte) (int, error) {
	buffers := getBuffer(len(bufs), offset+t.mtu+10)
	defer putBuffer(buffers)

	for i := range bufs {
		copy(buffers[i][offset:], bufs[i])
	}

	_, err := t.nt.Write(buffers, offset)
	if err != nil {
		return 0, err
	}

	return len(bufs), nil
}

func (t *wgReadWriteCloser) Close() error       { return t.nt.Close() }
func (t *wgReadWriteCloser) Device() wun.Device { return t.nt }
func (t *wgReadWriteCloser) BatchSize() int     { return t.Device().BatchSize() }

type poolType struct {
	batch int
	size  bool
}

var poolMap syncmap.SyncMap[poolType, *sync.Pool]

func buffPool(batch int, size bool) *sync.Pool {
	t := poolType{batch, size}
	if v, ok := poolMap.Load(t); ok {
		return v
	}

	var p *sync.Pool

	if size {
		p = &sync.Pool{
			New: func() any {
				return make([]int, batch)
			},
		}
	} else {
		p = &sync.Pool{New: func() any {
			return make([][]byte, batch)
		}}
	}
	poolMap.Store(t, p)
	return p
}

func getBuffer(batch, size int) [][]byte {
	bufs := buffPool(batch, false).Get().([][]byte)

	for i := range bufs {
		bufs[i] = pool.GetBytes(size)
	}

	return bufs
}

func putBuffer(bufs [][]byte) {
	for i := range bufs {
		pool.PutBytes(bufs[i])
	}
	buffPool(len(bufs), false).Put(bufs)
}

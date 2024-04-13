package tun

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	wun "github.com/tailscale/wireguard-go/tun"
)

type wgDevice struct {
	wun.Device
	mtu    int
	offset int
}

func NewDevice(device wun.Device, offset int) *wgDevice {
	mtu, _ := device.MTU()
	if mtu <= 0 {
		mtu = nat.MaxSegmentSize
	}
	wrwc := &wgDevice{
		Device: device,
		mtu:    mtu,
		offset: offset,
	}

	return wrwc
}

func (t *wgDevice) Read(bufs [][]byte, sizes []int) (n int, err error) {
	if t.offset == 0 && t.Device.BatchSize() == 1 {
		return t.Device.Read(bufs, sizes, t.offset)
	}

	buffers := getBuffer(t.BatchSize(), t.offset+t.mtu+10)
	defer putBuffer(buffers)
	size := buffPool(t.BatchSize(), true).Get().([]int)
	defer buffPool(t.BatchSize(), true).Put(size)

	count, err := t.Device.Read(buffers, size, t.offset)
	if err != nil {
		return 0, err
	}

	if count > len(bufs) {
		return 0, fmt.Errorf("buffer %d is smaller than recevied: %d", len(bufs), count)
	}

	for i := range bufs {
		copy(bufs[i], buffers[i][t.offset:size[i]+t.offset])
		sizes[i] = size[i]
	}

	return count, err
}

func (t *wgDevice) Write(bufs [][]byte) (int, error) {
	if t.offset == 0 && t.BatchSize() == 1 {
		return t.Device.Write(bufs, t.offset)
	}

	buffers := getBuffer(len(bufs), t.offset+t.mtu+10)
	defer putBuffer(buffers)

	for i := range bufs {
		copy(buffers[i][t.offset:], bufs[i])
	}

	_, err := t.Device.Write(buffers, t.offset)
	if err != nil {
		return 0, err
	}

	return len(bufs), nil
}

func (t *wgDevice) Tun() wun.Device { return t.Device }

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

type ChannelTun struct {
	mtu      int
	inbound  chan *pool.Bytes
	outbound chan *pool.Bytes
	ctx      context.Context
	cancel   context.CancelFunc
	events   chan wun.Event
}

func NewChannelTun(ctx context.Context, mtu int) *ChannelTun {
	if mtu <= 0 {
		mtu = nat.MaxSegmentSize
	}
	ctx, cancel := context.WithCancel(ctx)
	ct := &ChannelTun{
		mtu:      mtu,
		inbound:  make(chan *pool.Bytes, 10),
		outbound: make(chan *pool.Bytes, 10),
		ctx:      ctx,
		cancel:   cancel,
		events:   make(chan wun.Event, 1),
	}

	ct.events <- wun.EventUp

	return ct
}

func (p *ChannelTun) Outbound(b []byte) error {
	select {
	case p.outbound <- pool.GetBytesBuffer(p.mtu).Copy(b):
		return nil
	case <-p.ctx.Done():
		return io.ErrClosedPipe
	}
}

func (p *ChannelTun) Read(b [][]byte, size []int, offset int) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	select {
	case <-p.ctx.Done():
		return 0, io.EOF
	case bb := <-p.outbound:
		defer bb.Free()
		size[0] = copy(b[0][offset:], bb.Bytes())
		return 1, nil
	}
}

func (p *ChannelTun) Inbound(b []byte) (int, error) {
	select {
	case <-p.ctx.Done():
		return 0, io.EOF
	case bb := <-p.inbound:
		defer bb.Free()
		return copy(b, bb.Bytes()), nil
	}
}

func (p *ChannelTun) Write(b [][]byte, offset int) (int, error) {
	for _, bb := range b {
		select {
		case p.inbound <- pool.GetBytesBuffer(p.mtu).Copy(bb[offset:]):
			return len(b), nil
		case <-p.ctx.Done():
			return 0, io.ErrClosedPipe
		}
	}

	return len(b), nil
}

func (p *ChannelTun) Close() error {
	select {
	case <-p.ctx.Done():
		return nil
	default:
	}
	close(p.events)
	p.cancel()
	return nil
}

func (p *ChannelTun) BatchSize() int        { return 1 }
func (p *ChannelTun) Name() (string, error) { return "channelTun", nil }
func (p *ChannelTun) MTU() (int, error)     { return p.mtu, nil }
func (p *ChannelTun) File() *os.File        { return nil }

func (p *ChannelTun) Events() <-chan wun.Event { return p.events }

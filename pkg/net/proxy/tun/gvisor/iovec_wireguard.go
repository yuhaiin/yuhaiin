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

	rmu      sync.Mutex
	wmu      sync.Mutex
	wbuffers [][]byte
	rbuffers [][]byte
	rsize    []int
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

		wbuffers: getBuffer(device.BatchSize(), offset+mtu+10),
		rbuffers: getBuffer(device.BatchSize(), offset+mtu+10),
		rsize:    buffPool(device.BatchSize(), true).Get().([]int),
	}

	return wrwc
}

func (t *wgDevice) Read(bufs [][]byte, sizes []int) (n int, err error) {
	if t.offset == 0 && t.Device.BatchSize() == 1 {
		return t.Device.Read(bufs, sizes, t.offset)
	}

	t.rmu.Lock()
	defer t.rmu.Unlock()

	count, err := t.Device.Read(t.rbuffers, t.rsize, t.offset)
	if err != nil {
		return 0, err
	}

	if count > len(bufs) {
		return 0, fmt.Errorf("buffer %d is smaller than recevied: %d", len(bufs), count)
	}

	for i := range count {
		copy(bufs[i], t.rbuffers[i][t.offset:t.rsize[i]+t.offset])
		sizes[i] = t.rsize[i]
	}

	return count, err
}

func (t *wgDevice) Write(bufs [][]byte) (int, error) {
	if t.offset == 0 && t.BatchSize() == 1 {
		return t.Device.Write(bufs, t.offset)
	}

	if len(bufs) > len(t.wbuffers) {
		return 0, fmt.Errorf("buffer %d is larger than recevied: %d", len(t.wbuffers), len(bufs))
	}

	t.wmu.Lock()
	defer t.wmu.Unlock()

	buffs := buffPool(len(bufs), false).Get().([][]byte)
	defer buffPool(len(bufs), false).Put(buffs)

	for i := range bufs {
		n := copy(t.wbuffers[i][t.offset:], bufs[i])
		buffs[i] = t.wbuffers[i][:n+t.offset]
	}

	_, err := t.Device.Write(buffs, t.offset)
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
	inbound  chan []byte
	outbound chan []byte
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
		inbound:  make(chan []byte, 10),
		outbound: make(chan []byte, 10),
		ctx:      ctx,
		cancel:   cancel,
		events:   make(chan wun.Event, 1),
	}

	ct.events <- wun.EventUp

	return ct
}

func (p *ChannelTun) Outbound(b []byte) error {
	buf := pool.Clone(b)
	select {
	case p.outbound <- buf:
		return nil
	case <-p.ctx.Done():
		pool.PutBytes(buf)
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
		defer pool.PutBytes(bb)
		size[0] = copy(b[0][offset:], bb)
		return 1, nil
	}
}

func (p *ChannelTun) Inbound(b []byte) (int, error) {
	select {
	case <-p.ctx.Done():
		return 0, io.EOF
	case bb := <-p.inbound:
		defer pool.PutBytes(bb)
		return copy(b, bb), nil
	}
}

func (p *ChannelTun) Write(b [][]byte, offset int) (int, error) {
	for _, bb := range b {
		b := pool.Clone(bb)
		select {
		case p.inbound <- b:
			return len(b), nil
		case <-p.ctx.Done():
			pool.PutBytes(b)
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

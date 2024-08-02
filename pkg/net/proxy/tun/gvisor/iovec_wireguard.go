package tun

import (
	"context"
	"io"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
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

type ChannelTun struct {
	ctx      context.Context
	inbound  chan []byte
	outbound chan []byte
	cancel   context.CancelFunc
	events   chan wun.Event
	mtu      int
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
	p.cancel()
	close(p.events)
	return nil
}

func (p *ChannelTun) BatchSize() int        { return 1 }
func (p *ChannelTun) Name() (string, error) { return "channelTun", nil }
func (p *ChannelTun) MTU() (int, error)     { return p.mtu, nil }
func (p *ChannelTun) File() *os.File        { return nil }

func (p *ChannelTun) Events() <-chan wun.Event { return p.events }

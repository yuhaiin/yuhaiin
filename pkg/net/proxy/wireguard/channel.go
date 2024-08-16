package wireguard

import (
	"context"
	"io"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	wun "github.com/tailscale/wireguard-go/tun"
)

type ChannelDevice struct {
	ctx      context.Context
	inbound  chan []byte
	outbound chan []byte
	cancel   context.CancelFunc
	events   chan wun.Event
	mtu      int
}

func NewChannelDevice(ctx context.Context, mtu int) *ChannelDevice {
	if mtu <= 0 {
		mtu = nat.MaxSegmentSize
	}
	ctx, cancel := context.WithCancel(ctx)
	ct := &ChannelDevice{
		mtu:      mtu,
		inbound:  make(chan []byte, 250),
		outbound: make(chan []byte, 250),
		ctx:      ctx,
		cancel:   cancel,
		events:   make(chan wun.Event, 1),
	}

	ct.events <- wun.EventUp
	return ct
}

func (p *ChannelDevice) Outbound(b []byte) error {
	buf := pool.Clone(b)
	select {
	case p.outbound <- buf:
		return nil
	case <-p.ctx.Done():
		pool.PutBytes(buf)
		return io.ErrClosedPipe
	}
}

func (p *ChannelDevice) Read(b [][]byte, size []int, offset int) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	select {
	case <-p.ctx.Done():
		return 0, io.EOF
	case bb := <-p.outbound:
		size[0] = copy(b[0][offset:], bb)
		pool.PutBytes(bb)
		return 1, nil
	}
}

func (p *ChannelDevice) Inbound(b []byte) (int, error) {
	select {
	case <-p.ctx.Done():
		return 0, io.EOF
	case bb := <-p.inbound:
		defer pool.PutBytes(bb)
		return copy(b, bb), nil
	}
}

func (p *ChannelDevice) Write(b [][]byte, offset int) (int, error) {
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

func (p *ChannelDevice) Close() error {
	select {
	case <-p.ctx.Done():
		return nil
	default:
	}
	p.cancel()
	close(p.events)
	return nil
}

func (p *ChannelDevice) BatchSize() int           { return 1 }
func (p *ChannelDevice) Name() (string, error)    { return "channelTun", nil }
func (p *ChannelDevice) MTU() (int, error)        { return p.mtu, nil }
func (p *ChannelDevice) File() *os.File           { return nil }
func (p *ChannelDevice) Events() <-chan wun.Event { return p.events }

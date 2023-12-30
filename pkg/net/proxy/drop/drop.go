package drop

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"github.com/Asutorufa/yuhaiin/pkg/utils/singleflight"
)

func init() {
	point.RegisterProtocol(func(*protocol.Protocol_Drop) point.WrapProxy {
		return func(netapi.Proxy) (netapi.Proxy, error) { return Drop, nil }
	})
}

var Drop = &drop{
	lru: lru.NewLru[string, time.Duration](
		lru.WithCapacity[string, time.Duration](512),
		lru.WithExpireTimeout[string, time.Duration](time.Second*5),
	),
	sf: &singleflight.Group[string, time.Duration]{},
}

type drop struct {
	netapi.EmptyDispatch
	lru *lru.LRU[string, time.Duration]
	sf  *singleflight.Group[string, time.Duration]
}

func (d *drop) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	time := d.waitTime(addr)
	return NewDrop(ctx, time), nil
}

func (d *drop) waitTime(addr netapi.Address) time.Duration {
	time, _, _ := d.sf.Do(addr.String(), func() (time.Duration, error) {
		en, ok := d.lru.Load(addr.String())
		if ok {
			if en == 0 {
				en = time.Second
			} else if en < time.Second*30 {
				en *= 2
			}
		}

		d.lru.Add(addr.String(), en)

		return en, nil
	})

	return time
}

func (d *drop) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	time := d.waitTime(addr)
	return NewDrop(ctx, time), nil
}

var _ net.Conn = (*DropConn)(nil)

type DropConn struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func NewDrop(ctx context.Context, timeout time.Duration) *DropConn {
	if timeout == 0 {
		return &DropConn{}
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	return &DropConn{ctx, cancel}
}

func (d *DropConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	if d.ctx != nil {
		<-d.ctx.Done()
	}
	return 0, nil, io.EOF
}

func (d *DropConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return len(b), nil
}

func (d *DropConn) Read(b []byte) (n int, err error) {
	if d.ctx != nil {
		<-d.ctx.Done()
	}

	return 0, io.EOF
}

func (d *DropConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (d *DropConn) Close() error {
	if d.cancel != nil {
		d.cancel()
	}
	return nil
}

func (d *DropConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IP{0, 0, 0, 0}}
}

func (d *DropConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IP{0, 0, 0, 0}}
}

func (d *DropConn) SetDeadline(t time.Time) error { return nil }

func (d *DropConn) SetReadDeadline(t time.Time) error { return nil }

func (d *DropConn) SetWriteDeadline(t time.Time) error { return nil }

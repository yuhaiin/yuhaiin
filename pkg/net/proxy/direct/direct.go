package direct

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

type direct struct {
	netapi.EmptyDispatch
	iface string
}

func init() {
	register.RegisterPoint(func(p *protocol.Direct, _ netapi.Proxy) (netapi.Proxy, error) {
		if p.GetNetworkInterface() != "" {
			return &direct{iface: p.GetNetworkInterface()}, nil
		}
		return Default, nil
	})

	register.SetBootstrap(Default)
}

type PacketConnNoWarpKey struct{}

var Default netapi.Proxy = NewDirect()

func NewDirect() netapi.Proxy {
	return &direct{}
}

func (d *direct) Conn(ctx context.Context, s netapi.Address) (net.Conn, error) {
	if d.iface != "" {
		ctx = context.WithValue(ctx, dialer.NetworkInterfaceKey{}, d.iface)
	}
	return dialer.DialHappyEyeballsv2(ctx, s)
}

func (d *direct) PacketConn(ctx context.Context, _ netapi.Address) (net.PacketConn, error) {
	opts := []func(*dialer.Options){
		dialer.WithTryUpgradeToBatch(),
	}

	if d.iface != "" {
		ctx = context.WithValue(ctx, dialer.NetworkInterfaceKey{}, d.iface)
	}

	p, err := dialer.ListenPacket(ctx, "udp", "", opts...)
	if err != nil {
		return nil, fmt.Errorf("listen packet failed: %w", err)
	}

	if ctx.Value(PacketConnNoWarpKey{}) == true {
		return p, nil
	}

	return &UDPPacketConn{context.WithoutCancel(ctx), NewBufferPacketConn(p)}, nil
}

func (d *direct) Close() error { return nil }

type BufferPacketConn interface {
	net.PacketConn
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

func NewBufferPacketConn(p net.PacketConn) BufferPacketConn {
	x, ok := p.(BufferPacketConn)
	if ok {
		return x
	}
	return &bufferPacketConn{p}
}

type bufferPacketConn struct{ net.PacketConn }

func (p *bufferPacketConn) SetReadBuffer(int) error  { return nil }
func (p *bufferPacketConn) SetWriteBuffer(int) error { return nil }

type UDPPacketConn struct {
	ctx context.Context
	BufferPacketConn
}

func (p *UDPPacketConn) WriteTo(b []byte, addr net.Addr) (_ int, err error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		a, err := netapi.ParseSysAddr(addr)
		if err != nil {
			return 0, err
		}

		ctx, cancel := context.WithTimeout(p.ctx, time.Second*5)
		defer cancel()
		udpAddr, err = dialer.ResolveUDPAddr(ctx, a)
		if err != nil {
			return 0, err
		}
	}

	return p.BufferPacketConn.WriteTo(b, udpAddr)
}

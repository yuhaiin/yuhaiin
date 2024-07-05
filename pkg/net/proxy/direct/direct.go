package direct

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
)

type direct struct{ netapi.EmptyDispatch }

func init() {
	point.RegisterProtocol(func(p *protocol.Protocol_Direct) point.WrapProxy {
		return func(netapi.Proxy) (netapi.Proxy, error) {
			return Default, nil
		}
	})

	point.SetBootstrap(Default)
}

var Default netapi.Proxy = NewDirect()

func NewDirect() netapi.Proxy {
	return &direct{}
}

func (d *direct) Conn(ctx context.Context, s netapi.Address) (net.Conn, error) {
	return netapi.DialHappyEyeballs(ctx, s)
}

func (d *direct) PacketConn(ctx context.Context, _ netapi.Address) (net.PacketConn, error) {
	p, err := dialer.ListenPacket("udp", "")
	if err != nil {
		return nil, fmt.Errorf("listen packet failed: %w", err)
	}

	return &PacketConn{context.WithoutCancel(ctx), p}, nil
}

type PacketConn struct {
	ctx context.Context
	net.PacketConn
}

func (p *PacketConn) WriteTo(b []byte, addr net.Addr) (_ int, err error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		a, err := netapi.ParseSysAddr(addr)
		if err != nil {
			return 0, err
		}

		// _, file, line, _ := runtime.Caller(2)
		// _, file3, line3, _ := runtime.Caller(3)
		// _, file2, line2, _ := runtime.Caller(4)
		// slog.Info("---------------------------------direct proxy dns",
		// 	"fqdn", a.String(),
		// 	"skip", netapi.GetContext(p.ctx).Resolver.SkipResolve,
		// 	"mode", netapi.GetContext(p.ctx).Mode,
		// 	"type", reflect.TypeOf(addr),
		// 	"call from", fmt.Sprintf("%s:%d", file, line),
		// 	"call 3", fmt.Sprintf("%s:%d", file3, line3),
		// 	"call 2", fmt.Sprintf("%s:%d", file2, line2),
		// )

		ctx, cancel := context.WithTimeout(p.ctx, time.Second*5)
		defer cancel()
		udpAddr, err = netapi.ResolveUDPAddr(ctx, a)
		if err != nil {
			return 0, err
		}
	}

	return p.PacketConn.WriteTo(b, udpAddr)
}

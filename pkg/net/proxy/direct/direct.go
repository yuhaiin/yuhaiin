package direct

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
)

type direct struct {
	netapi.EmptyDispatch
	timeout time.Duration
}

func init() {
	point.RegisterProtocol(func(p *protocol.Protocol_Direct) point.WrapProxy {
		return func(netapi.Proxy) (netapi.Proxy, error) {
			if p.Direct.Timeout <= 0 {
				return Default, nil
			}

			return NewDirect(time.Duration(p.Direct.Timeout) * time.Second), nil
		}
	})

	point.SetBootstrap(Default)
}

var Default netapi.Proxy = NewDirect(time.Second * 3)

func NewDirect(timeout time.Duration) netapi.Proxy {
	if timeout <= 0 {
		timeout = time.Second * 3
	}
	return &direct{
		timeout: timeout,
	}
}

func (d *direct) Conn(ctx context.Context, s netapi.Address) (net.Conn, error) {

	ips, err := s.IPs(ctx)
	if err != nil {
		return nil, fmt.Errorf("get ip failed: %w", err)
	}

	ctx = context.WithoutCancel(ctx)

	for _, i := range rand.Perm(len(ips)) {
		host := net.JoinHostPort(ips[i].String(), s.Port().String())
		ctx, cancel := context.WithTimeout(ctx, d.timeout)
		var conn net.Conn
		conn, err = dialer.DialContext(ctx, "tcp", host)
		cancel()
		if err != nil {
			continue
		}
		return conn, nil
	}

	return nil, fmt.Errorf("dial failed: %w", err)
}

func (d *direct) PacketConn(context.Context, netapi.Address) (net.PacketConn, error) {
	p, err := dialer.ListenPacket("udp", "")
	if err != nil {
		return nil, fmt.Errorf("listen packet failed: %w", err)
	}

	return &PacketConn{p}, nil
}

type PacketConn struct{ net.PacketConn }

func (p *PacketConn) WriteTo(b []byte, addr net.Addr) (_ int, err error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		a, err := netapi.ParseSysAddr(addr)
		if err != nil {
			return 0, err
		}

		ur := a.UDPAddr(context.TODO())
		if ur.Err != nil {
			return 0, ur.Err
		}

		udpAddr = ur.V
	}

	return p.PacketConn.WriteTo(b, udpAddr)
}

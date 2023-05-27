package direct

import (
	"context"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
)

type direct struct{ proxy.EmptyDispatch }

var Default proxy.Proxy = NewDirect()

func NewDirect() proxy.Proxy { return &direct{} }

func (d *direct) Conn(ctx context.Context, s proxy.Address) (net.Conn, error) {
	ip, err := s.IP(ctx)
	if err != nil {
		return nil, fmt.Errorf("get ip failed: %w", err)
	}
	return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), s.Port().String()))
}

func (d *direct) PacketConn(context.Context, proxy.Address) (net.PacketConn, error) {
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
		a, err := proxy.ParseSysAddr(addr)
		if err != nil {
			return 0, err
		}

		udpAddr, err = a.UDPAddr(context.TODO())
		if err != nil {
			return 0, err
		}
	}

	return p.PacketConn.WriteTo(b, udpAddr)
}

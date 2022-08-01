package direct

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
)

type direct struct{}

var Default proxy.Proxy = NewDirect()

func NewDirect() proxy.Proxy { return &direct{} }

func (d *direct) Conn(s proxy.Address) (net.Conn, error) {
	host, err := s.IPHost()
	if err != nil {
		return nil, fmt.Errorf("get host failed: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()
	return dialer.DialContext(ctx, "tcp", host)
}

func (d *direct) PacketConn(proxy.Address) (net.PacketConn, error) {
	p, err := dialer.ListenPacket("udp", "")
	if err != nil {
		return nil, fmt.Errorf("listen packet failed: %w", err)
	}

	return &packetConn{PacketConn: p}, nil
}

type packetConn struct{ net.PacketConn }

func (p *packetConn) WriteTo(b []byte, addr net.Addr) (_ int, err error) {
	switch z := addr.(type) {
	case *net.UDPAddr:
	case proxy.Address:
		addr, err = z.UDPAddr()
		if err != nil {
			return 0, err
		}
	default:
		a, err := proxy.ParseSysAddr(addr)
		if err != nil {
			return 0, err
		}
		addr, err = a.UDPAddr()
		if err != nil {
			return 0, err
		}
	}

	// log.Println("write to", addr, len(b))

	return p.PacketConn.WriteTo(b, addr)
}

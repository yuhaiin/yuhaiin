package direct

import (
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
)

type direct struct{ proxy.EmptyDispatch }

var Default proxy.Proxy = NewDirect()

func NewDirect() proxy.Proxy { return &direct{} }

func (d *direct) Conn(s proxy.Address) (net.Conn, error) {
	ip, err := s.IP()
	if err != nil {
		return nil, fmt.Errorf("get ip failed: %w", err)
	}
	return dialer.DialContext(s.Context(), "tcp", net.JoinHostPort(ip.String(), s.Port().String()))
}

func (d *direct) PacketConn(proxy.Address) (net.PacketConn, error) {
	p, err := dialer.ListenPacket("udp", "")
	if err != nil {
		return nil, fmt.Errorf("listen packet failed: %w", err)
	}

	return &PacketConn{PacketConn: p}, nil
}

type PacketConn struct{ net.PacketConn }

func (p *PacketConn) WriteTo(b []byte, addr net.Addr) (_ int, err error) {
	a, err := proxy.ParseSysAddr(addr)
	if err != nil {
		return 0, err
	}
	addr, err = a.UDPAddr()
	if err != nil {
		return 0, err
	}

	return p.PacketConn.WriteTo(b, addr)
}

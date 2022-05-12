package direct

import (
	"context"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
)

type direct struct {
	listener *net.ListenConfig
}

var Default proxy.Proxy = NewDirect()

func NewDirect() proxy.Proxy { return &direct{listener: &net.ListenConfig{}} }

func (d *direct) Conn(s proxy.Address) (net.Conn, error) {
	return (&net.Dialer{Timeout: time.Second * 10}).Dial("tcp", s.IPHost())
}

func (d *direct) PacketConn(proxy.Address) (net.PacketConn, error) {
	return d.listener.ListenPacket(context.TODO(), "udp", "")
}

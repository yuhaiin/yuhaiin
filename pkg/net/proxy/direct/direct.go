package direct

import (
	"context"
	"fmt"
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
	host, err := s.IPHost()
	if err != nil {
		return nil, fmt.Errorf("get host failed: %w", err)
	}
	return (&net.Dialer{Timeout: time.Second * 10}).Dial("tcp", host)
}

func (d *direct) PacketConn(proxy.Address) (net.PacketConn, error) {
	return d.listener.ListenPacket(context.TODO(), "udp", "")
}

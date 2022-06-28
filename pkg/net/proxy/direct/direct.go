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
	return dialer.ListenPacket("udp", "")
}

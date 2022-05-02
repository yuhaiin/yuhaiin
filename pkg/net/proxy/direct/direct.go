package direct

import (
	"context"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

type direct struct {
	dialer   *net.Dialer
	listener *net.ListenConfig
}

type Option func(*direct)

func WithLookup(dns dns.DNS) Option {
	return func(d *direct) {
		d.dialer.Resolver = dns.Resolver()
	}
}

var Default proxy.Proxy = NewDirect()

func NewDirect(o ...Option) proxy.Proxy {
	d := &direct{
		dialer: &net.Dialer{
			Timeout: time.Second * 10,
		},
		listener: &net.ListenConfig{},
	}

	for _, opt := range o {
		opt(d)
	}

	return d
}

func (d *direct) Conn(s string) (net.Conn, error) {
	return d.dialer.Dial("tcp", s)
}

func (d *direct) PacketConn(string) (net.PacketConn, error) {
	return d.listener.ListenPacket(context.TODO(), "udp", "")
}

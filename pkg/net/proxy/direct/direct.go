package direct

import (
	"context"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

type direct struct {
	dns      dns.DNS
	listener *net.ListenConfig
}

type Option func(*direct)

func WithLookup(dns dns.DNS) Option {
	return func(d *direct) {
		if dns == nil {
			return
		}
		d.dns = dns
	}
}

var Default proxy.Proxy = NewDirect()

func NewDirect(o ...Option) proxy.Proxy {
	d := &direct{listener: &net.ListenConfig{}, dns: dns.DefaultDNS}

	for _, opt := range o {
		opt(d)
	}
	return d
}

func (d *direct) Conn(s string) (net.Conn, error) {
	return (&net.Dialer{Timeout: time.Second * 10, Resolver: d.dns.Resolver()}).Dial("tcp", s)
}

func (d *direct) PacketConn(string) (net.PacketConn, error) {
	return d.listener.ListenPacket(context.TODO(), "udp", "")
}

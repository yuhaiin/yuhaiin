package direct

import (
	"context"
	"math/rand"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils/resolver"
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
	d := &direct{listener: &net.ListenConfig{}, dns: resolver.Bootstrap}

	for _, opt := range o {
		opt(d)
	}
	return d
}

func (d *direct) Conn(s proxy.Address) (net.Conn, error) {
	host := s.String()
	if s.Type() == proxy.DOMAIN {
		x, err := d.dns.LookupIP(s.Hostname())
		if err != nil {
			return nil, err
		}

		host = net.JoinHostPort(x[rand.Intn(len(x))].String(), s.Port().String())
	}

	return (&net.Dialer{Timeout: time.Second * 10}).Dial("tcp", host)
}

func (d *direct) PacketConn(proxy.Address) (net.PacketConn, error) {
	return d.listener.ListenPacket(context.TODO(), "udp", "")
}

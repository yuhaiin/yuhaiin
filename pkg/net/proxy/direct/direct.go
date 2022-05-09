package direct

import (
	"context"
	"fmt"
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

func (d *direct) Conn(s string) (net.Conn, error) {
	address, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %s", s)
	}

	if net.ParseIP(address) == nil {
		x, err := d.dns.LookupIP(address)
		if err != nil {
			return nil, err
		}

		s = net.JoinHostPort(x[rand.Intn(len(x))].String(), port)
	}

	return (&net.Dialer{Timeout: time.Second * 10}).Dial("tcp", s)
}

func (d *direct) PacketConn(string) (net.PacketConn, error) {
	return d.listener.ListenPacket(context.TODO(), "udp", "")
}

package simple

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils/resolver"
)

//Simple .
type Simple struct {
	addr proxy.Address

	lookupIP  func(host string) ([]net.IP, error)
	tlsConfig *tls.Config
}

func WithLookupIP(f func(host string) ([]net.IP, error)) func(*Simple) {
	return func(cu *Simple) {
		if f == nil {
			return
		}
		cu.lookupIP = f
	}
}

func WithTLS(t *tls.Config) func(*Simple) {
	return func(c *Simple) {
		c.tlsConfig = t
	}
}

//NewSimple .
func NewSimple(address proxy.Address, opts ...func(*Simple)) proxy.Proxy {
	c := &Simple{addr: address, lookupIP: resolver.LookupIP}

	for i := range opts {
		opts[i](c)
	}

	return c
}

var clientDialer = net.Dialer{Timeout: time.Second * 5}

func (c *Simple) Conn(proxy.Address) (net.Conn, error) {
	address := c.addr.String()

	if c.addr.Type() == proxy.DOMAIN {
		x, err := c.lookupIP(c.addr.Hostname())
		if err != nil {
			return nil, err
		}

		address = net.JoinHostPort(x[rand.Intn(len(x))].String(), c.addr.Port().String())
	}

	conn, err := clientDialer.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("simple dial failed: %w", err)
	}

	if c.tlsConfig != nil {
		conn = tls.Client(conn, c.tlsConfig)
	}

	return conn, nil
}

func (c *Simple) PacketConn(proxy.Address) (net.PacketConn, error) {
	return net.ListenPacket("udp", "")
}

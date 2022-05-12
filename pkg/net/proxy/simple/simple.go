package simple

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
)

//Simple .
type Simple struct {
	addr proxy.Address

	tlsConfig *tls.Config
}

//NewSimple .
func NewSimple(address proxy.Address, tls *tls.Config) proxy.Proxy {
	return &Simple{addr: address, tlsConfig: tls}
}

var clientDialer = net.Dialer{Timeout: time.Second * 5}

func (c *Simple) Conn(proxy.Address) (net.Conn, error) {
	conn, err := clientDialer.Dial("tcp", c.addr.IPHost())
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

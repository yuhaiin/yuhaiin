package simple

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
)

// Simple .
type Simple struct {
	addr proxy.Address

	tlsConfig *tls.Config
}

// NewSimple .
func NewSimple(address proxy.Address, tls *tls.Config) proxy.Proxy {
	return &Simple{addr: address, tlsConfig: tls}
}

func (c *Simple) Conn(proxy.Address) (net.Conn, error) {
	host, err := c.addr.IPHost()
	if err != nil {
		return nil, fmt.Errorf("get host failed: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("simple dial failed: %w", err)
	}

	if c.tlsConfig != nil {
		conn = tls.Client(conn, c.tlsConfig)
	}

	return conn, nil
}

func (c *Simple) PacketConn(proxy.Address) (net.PacketConn, error) {
	return dialer.ListenPacket("udp", "")
}

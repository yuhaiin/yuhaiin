package tls

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
)

var _ net.Conn = (*unWrapConn)(nil)

func init() {
	register.RegisterPoint(NewUnWrapTls)
}

type unWrapTls struct {
	netapi.Proxy
	config *tls.Config
}

func NewUnWrapTls(c *protocol.UnwrapTls, p netapi.Proxy) (netapi.Proxy, error) {
	config, err := register.ParseTLS(c.GetTls())
	if err != nil {
		return nil, err
	}

	return &unWrapTls{
		Proxy:  p,
		config: config,
	}, nil
}

func (u *unWrapTls) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	conn, err := u.Proxy.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	return newUnWrapConn(conn, u.config), nil
}

type unWrapConn struct {
	net.Conn
	srcpipe *pipe.Conn
	dstpipe *pipe.Conn
	conn    *tls.Conn
}

func newUnWrapConn(conn net.Conn, config *tls.Config) *unWrapConn {
	src, dst := pipe.Pipe()

	tlsConn := tls.Server(src, config)

	go relay.Relay(conn, tlsConn)

	h := &unWrapConn{
		Conn:    conn,
		srcpipe: src,
		dstpipe: dst,
		conn:    tlsConn,
	}

	return h
}

func (u *unWrapConn) Write(p []byte) (n int, err error) { return u.dstpipe.Write(p) }
func (u *unWrapConn) Read(p []byte) (n int, err error)  { return u.dstpipe.Read(p) }

func (u *unWrapConn) Close() error {
	u.conn.Close()
	u.srcpipe.Close()
	u.dstpipe.Close()
	return u.Conn.Close()
}

package tls

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
)

func init() {
	register.RegisterPoint(NewUnWrapTls)
}

type unWrapTls struct {
	netapi.Proxy
	config *tls.Config
}

func NewUnWrapTls(c *node.TlsTermination, p netapi.Proxy) (netapi.Proxy, error) {
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

	if httpTermination, ok := conn.(interface{ SetTLSTermination(ok bool) }); ok {
		httpTermination.SetTLSTermination(true)
	}

	return newUnWrapConn(conn, u.config), nil
}

var _ net.Conn = (*unWrapConn)(nil)

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

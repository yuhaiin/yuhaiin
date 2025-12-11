package proxy

import (
	"net"
	"strconv"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/net/nettest"
	"google.golang.org/protobuf/proto"
)

func TestProxy(t *testing.T) {
	lis, err := nettest.NewLocalListener("tcp")
	assert.NoError(t, err)
	defer lis.Close()

	_, portstr, err := net.SplitHostPort(lis.Addr().String())
	assert.NoError(t, err)

	port, err := strconv.ParseUint(portstr, 10, 16)
	assert.NoError(t, err)

	p, err := fixed.NewClient(node.Fixed_builder{
		Host: proto.String("127.0.0.1"),
		Port: proto.Int32(int32(port)),
	}.Build(), nil)
	assert.NoError(t, err)

	p, err = NewClient(&node.Proxy{}, p)
	assert.NoError(t, err)
	defer p.Close()

	s, err := NewServer(&config.Proxy{}, netapi.NewListener(lis, nil))
	assert.NoError(t, err)

	ch := make(chan net.Conn, 1)
	cch := make(chan net.Conn, 1)

	go func() {
		for {
			conn, err := s.Accept()
			if err != nil {
				break
			}

			ch <- conn
		}
	}()

	nettest.TestConn(t, func() (c1 net.Conn, c2 net.Conn, stop func(), err error) {
		go func() {
			conn, err := p.Conn(t.Context(), netapi.EmptyAddr)
			assert.NoError(t, err)
			cch <- conn
		}()

		conns := make([]net.Conn, 0, 2)
		for len(conns) < 2 {
			select {
			case conn := <-cch:
				conns = append(conns, conn)
			case conn := <-ch:
				conns = append(conns, conn)
			}

		}

		return conns[0], conns[1], func() {
			conns[0].Close()
			conns[1].Close()
		}, nil
	})
}

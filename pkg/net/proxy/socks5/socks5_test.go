package socks5

import (
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/net/nettest"
	"google.golang.org/protobuf/proto"
)

func TestSocks5(t *testing.T) {
	newTest := func(t *testing.T, server listener.Socks5_builder, client protocol.Socks5_builder) (c1 net.Conn, c2 net.Conn, stop func(), err error) {
		lis, err := nettest.NewLocalListener("tcp")
		assert.NoError(t, err)

		ch := netapi.NewChannelHandler(t.Context())

		acc, err := NewServer(
			server.Build(),
			netapi.NewListener(lis, nil),
			ch,
		)
		assert.NoError(t, err)

		sp, err := fixed.NewClient(protocol.Fixed_builder{
			Host: proto.String("127.0.0.1"),
			Port: proto.Int32(int32(lis.Addr().(*net.TCPAddr).Port)),
		}.Build(), nil)
		assert.NoError(t, err)

		s5c, err := NewClient(
			client.Build(),
			sp,
		)
		assert.NoError(t, err)

		ea, err := netapi.ParseAddressPort("tcp", "www.example.com", 443)
		assert.NoError(t, err)

		dst, err := s5c.Conn(t.Context(), ea)
		assert.NoError(t, err)

		src := <-ch.Stream()

		return src.Src, dst, func() {
			lis.Close()
			acc.Close()
			s5c.Close()
			sp.Close()
			src.Src.Close()
			dst.Close()
		}, nil
	}

	t.Run("plain", func(t *testing.T) {
		t.Run("tcp", func(t *testing.T) {

			nettest.TestConn(t, func() (c1 net.Conn, c2 net.Conn, stop func(), err error) {
				return newTest(t,
					listener.Socks5_builder{
						Udp: proto.Bool(false),
					},
					protocol.Socks5_builder{},
				)
			})
		})
	})

	t.Run("auth", func(t *testing.T) {
		t.Run("tcp", func(t *testing.T) {

			nettest.TestConn(t, func() (c1 net.Conn, c2 net.Conn, stop func(), err error) {
				return newTest(t,
					listener.Socks5_builder{
						Udp:      proto.Bool(false),
						Username: proto.String("user"),
						Password: proto.String("pass"),
					},
					protocol.Socks5_builder{
						User:     proto.String("user"),
						Password: proto.String("pass"),
					},
				)
			})
		})
	})
}

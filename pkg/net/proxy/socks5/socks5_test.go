package socks5

import (
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/net/nettest"
)

func TestSocks5(t *testing.T) {
	newTest := func(t *testing.T, server ServerConfig, client Config) (c1 net.Conn, c2 net.Conn, stop func(), err error) {
		lis, err := nettest.NewLocalListener("tcp")
		assert.NoError(t, err)

		ch := netapi.NewChannelHandler(t.Context())

		acc, err := NewServer(
			server,
			netapi.NewListener(lis, nil),
			ch,
		)
		assert.NoError(t, err)

		sp, err := fixed.NewClient(fixed.Config{Host: "127.0.0.1", Port: int32(lis.Addr().(*net.TCPAddr).Port)}, nil)
		assert.NoError(t, err)

		s5c, err := NewClient(
			client,
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
					ServerConfig{},
					Config{},
				)
			})
		})
	})

	t.Run("auth", func(t *testing.T) {
		t.Run("tcp", func(t *testing.T) {

			nettest.TestConn(t, func() (c1 net.Conn, c2 net.Conn, stop func(), err error) {
				return newTest(t,
					ServerConfig{
						Username: "user",
						Password: "pass",
					},
					Config{
						User:     "user",
						Password: "pass",
					},
				)
			})
		})
	})
}

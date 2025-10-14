package aead

import (
	"fmt"
	"io"
	"net"
	"slices"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/net/nettest"
	"google.golang.org/protobuf/proto"
)

func TestAead(t *testing.T) {
	lis, err := nettest.NewLocalListener("tcp")
	assert.NoError(t, err)

	s, err := NewServer(listener.Aead_builder{
		Password:     proto.String("testsfsdfsf"),
		CryptoMethod: protocol.AeadCryptoMethod_XChacha20Poly1305.Enum(),
	}.Build(), netapi.NewListener(lis, nil))
	assert.NoError(t, err)
	defer s.Close()

	ch := make(chan net.Conn, 10)
	go func() {
		for {
			conn, err := s.Accept()
			if err != nil {
				break
			}

			ch <- conn
		}
	}()

	addr, err := netapi.ParseAddress("tcp", lis.Addr().String())
	assert.NoError(t, err)

	p, err := fixed.NewClient(protocol.Fixed_builder{
		Host: proto.String(addr.Hostname()),
		Port: proto.Int32(int32(addr.Port())),
	}.Build(), nil)
	assert.NoError(t, err)
	defer p.Close()

	c, err := NewClient(protocol.Aead_builder{
		Password:     proto.String("testsfsdfsf"),
		CryptoMethod: protocol.AeadCryptoMethod_XChacha20Poly1305.Enum(),
	}.Build(), p)
	assert.NoError(t, err)
	defer c.Close()

	// we can't test aead by nettest.TestConn, because the nonce will increase
	// even the write failed
	//
	// nettest.TestConn(t, func() (c1 net.Conn, c2 net.Conn, stop func(), err error) {
	// 	conn, err := c.Conn(t.Context(), netapi.EmptyAddr)
	// 	assert.NoError(t, err)

	// 	srv := <-ch

	// 	return conn, srv, func() {
	// 		conn.Close()
	// 		srv.Close()
	// 	}, nil
	// })

	conn, err := c.Conn(t.Context(), netapi.EmptyAddr)
	assert.NoError(t, err)

	srv := <-ch

	go func() {
		defer srv.Close()

		for i := range 10 {
			fmt.Fprint(srv, i)
		}
	}()

	buf := make([]byte, 10)

	count := 0
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				t.Fatal(err)
			}
			break
		}

		assert.Equal(t, fmt.Sprintf("%d", count), string(buf[:n]))
		count++
	}
}

func TestDecrement(t *testing.T) {
	for _, v := range [][]byte{
		{255, 255, 255, 254},
		{255, 255, 255, 255},
		{0, 255, 0, 0},
		{255, 255, 0, 0},
		{0, 0, 0, 0},
		{0, 1, 0, 0},
	} {
		z := slices.Clone(v)
		increment(z)
		decrement(z)
		assert.MustEqual(t, v, z)
	}
}

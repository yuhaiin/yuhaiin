package yuubinsya

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/net/nettest"
	"google.golang.org/protobuf/proto"
)

func TestServer(t *testing.T) {
	t.Run("http", func(t *testing.T) {
		lis, err := nettest.NewLocalListener("tcp")
		assert.NoError(t, err)
		defer lis.Close()

		a, err := NewServer(&listener.Yuubinsya{}, &mockListener{lis}, mockHandler(func(req *netapi.StreamMeta) {
			defer req.Src.Close()

			data := make([]byte, 4096)

			n, err := req.Src.Read(data)
			assert.NoError(t, err)

			_, _ = req.Src.Write(data[:n])
		}))
		assert.NoError(t, err)
		defer a.Close()

		req, err := http.NewRequest("POST", "http://"+lis.Addr().String(), nil)
		assert.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()
	})

	t.Run("client", func(t *testing.T) {
		lis, err := nettest.NewLocalListener("tcp")
		assert.NoError(t, err)
		defer lis.Close()

		a, err := NewServer(listener.Yuubinsya_builder{
			Password: proto.String("aaaa"),
		}.Build(), &mockListener{lis}, mockHandler(func(req *netapi.StreamMeta) {
			defer req.Src.Close()

			data := make([]byte, 4096)

			n, err := req.Src.Read(data)
			assert.NoError(t, err)

			_, _ = req.Src.Write(data[:n])
		}))
		assert.NoError(t, err)
		defer a.Close()

		host, portstr, err := net.SplitHostPort(lis.Addr().String())
		assert.NoError(t, err)

		port, err := strconv.ParseUint(portstr, 10, 16)
		assert.NoError(t, err)

		s, err := simple.NewClient(protocol.Simple_builder{
			Host: proto.String(host),
			Port: proto.Int32(int32(port)),
		}.Build(), nil)
		assert.NoError(t, err)

		c, err := NewClient(protocol.Yuubinsya_builder{
			Password: proto.String("aaaa"),
		}.Build(), s)
		assert.NoError(t, err)

		cx, err := c.Conn(t.Context(), netapi.EmptyAddr)
		if err == nil {
			defer cx.Close()
		}

		data := "czcasofjdsocobfierwu3892fhcbxkzkcjzc"
		_, err = cx.Write([]byte(data))
		assert.NoError(t, err)

		srcdata := make([]byte, 4096)
		n, err := cx.Read(srcdata)
		assert.NoError(t, err)

		assert.MustEqual(t, data, string(srcdata[:n]))
	})

	t.Run("test conn", func(t *testing.T) {
		nettest.TestConn(t, func() (c1, c2 net.Conn, stop func(), err error) {
			lis, err := nettest.NewLocalListener("tcp")
			assert.NoError(t, err)

			ch := make(chan *netapi.StreamMeta, 1)
			defer close(ch)

			ctx, cancel := context.WithCancel(context.Background())

			a, err := NewServer(listener.Yuubinsya_builder{
				Password: proto.String("aaaa"),
			}.Build(), &mockListener{lis}, mockHandler(func(req *netapi.StreamMeta) {
				ch <- req

				<-ctx.Done()
			}))
			assert.NoError(t, err)

			host, portstr, err := net.SplitHostPort(lis.Addr().String())
			assert.NoError(t, err)

			port, err := strconv.ParseUint(portstr, 10, 16)
			assert.NoError(t, err)

			s, err := simple.NewClient(protocol.Simple_builder{
				Host: proto.String(host),
				Port: proto.Int32(int32(port)),
			}.Build(), nil)
			assert.NoError(t, err)

			c, err := NewClient(protocol.Yuubinsya_builder{
				Password: proto.String("aaaa"),
			}.Build(), s)
			assert.NoError(t, err)

			cx, err := c.Conn(t.Context(), netapi.EmptyAddr)
			if err != nil {
				cancel()
				return nil, nil, nil, err
			}

			src := <-ch

			return cx, src.Src, func() {
				cancel()
				src.Src.Close()
				cx.Close()
				a.Close()
				lis.Close()
			}, nil
		})
	})
}

type mockListener struct{ l net.Listener }

func (l *mockListener) Packet(context.Context) (net.PacketConn, error) {
	return nil, errors.ErrUnsupported
}

func (l *mockListener) Stream(context.Context) (net.Listener, error) {
	return l.l, nil
}

func (l *mockListener) Close() error {
	return l.l.Close()
}

type mockHandler func(req *netapi.StreamMeta)

func (m mockHandler) HandleStream(req *netapi.StreamMeta) { m(req) }
func (m mockHandler) HandlePacket(req *netapi.Packet)     {}

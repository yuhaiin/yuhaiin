package http2

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"os"
	"strconv"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/net/nettest"
	"google.golang.org/protobuf/proto"
)

func TestConn(t *testing.T) {
	t.Run("context cancel", func(t *testing.T) {
		lis, err := nettest.NewLocalListener("tcp")
		assert.NoError(t, err)

		// t.Log("new server", lis.Addr().String())

		lis = newServer(lis)

		ch := make(chan net.Conn, 1)
		go func() {
			first := true
			for {
				conn, err := lis.Accept()
				if err != nil {
					break
				}

				if first {
					conn.Close()
					first = false
					continue
				}

				ch <- conn
			}
		}()

		host, portstr, err := net.SplitHostPort(lis.Addr().String())
		assert.NoError(t, err)

		port, err := strconv.ParseUint(portstr, 10, 16)
		assert.NoError(t, err)

		p, err := fixed.NewClient(node.Fixed_builder{
			Host: proto.String(host),
			Port: proto.Int32(int32(port)),
		}.Build(), nil)
		assert.NoError(t, err)

		p, err = NewClient(node.Http2_builder{
			Concurrency: proto.Int32(1),
		}.Build(), p)
		assert.NoError(t, err)

		cch := make(chan net.Conn, 1)
		go func() {
			ctx, cancel := context.WithCancel(context.TODO())
			defer cancel()
			conn, err := p.Conn(ctx, netapi.EmptyAddr)
			assert.NoError(t, err)
			conn.Close()
			conn, err = p.Conn(ctx, netapi.EmptyAddr)
			assert.NoError(t, err)
			cch <- conn
		}()

		src := <-ch
		dst := <-cch

		defer src.Close()
		defer dst.Close()

		go func() {
			defer src.Close()
			buf := make([]byte, 2048)
			_, _ = rand.Read(buf)
			for range 1000 {
				_, err = src.Write(buf)
				assert.NoError(t, err)
			}
		}()

		sum := 0

		for {
			buf := make([]byte, 5)
			n, err := dst.Read(buf)
			sum += n
			if err != nil {
				break
			}
		}

		assert.Equal(t, sum, 2048*1000)
	})

	t.Run("conn -> server", func(t *testing.T) {
		nettest.TestConn(t, func() (c1 net.Conn, c2 net.Conn, stop func(), err error) {
			lis, err := nettest.NewLocalListener("tcp")
			assert.NoError(t, err)

			// t.Log("new server", lis.Addr().String())

			lis = newServer(lis)

			ch := make(chan net.Conn, 1)
			go func() {
				for {
					conn, err := lis.Accept()
					if err != nil {
						break
					}

					ch <- conn
				}
			}()

			host, portstr, err := net.SplitHostPort(lis.Addr().String())
			assert.NoError(t, err)

			port, err := strconv.ParseUint(portstr, 10, 16)
			assert.NoError(t, err)

			p, err := fixed.NewClient(node.Fixed_builder{
				Host: proto.String(host),
				Port: proto.Int32(int32(port)),
			}.Build(), nil)
			assert.NoError(t, err)

			p, err = NewClient(node.Http2_builder{
				Concurrency: proto.Int32(1),
			}.Build(), p)
			assert.NoError(t, err)

			conn, err := p.Conn(context.TODO(), netapi.EmptyAddr)
			assert.NoError(t, err)

			src := <-ch

			// t.Log("new client", conn.RemoteAddr().String(), src, conn)

			return src, conn, func() {
				src.Close()
				conn.Close()
				p.Close()
				lis.Close()
			}, nil
		})
	})

	t.Run("server -> conn", func(t *testing.T) {
		nettest.TestConn(t, func() (c1 net.Conn, c2 net.Conn, stop func(), err error) {
			lis, err := nettest.NewLocalListener("tcp")
			assert.NoError(t, err)

			// t.Log("new server", lis.Addr().String())

			lis = newServer(lis)

			ch := make(chan net.Conn, 1)
			go func() {
				for {
					conn, err := lis.Accept()
					if err != nil {
						break
					}

					ch <- conn
				}
			}()

			host, portstr, err := net.SplitHostPort(lis.Addr().String())
			assert.NoError(t, err)

			port, err := strconv.ParseUint(portstr, 10, 16)
			assert.NoError(t, err)

			p, err := fixed.NewClient(node.Fixed_builder{
				Host: proto.String(host),
				Port: proto.Int32(int32(port)),
			}.Build(), nil)
			assert.NoError(t, err)

			p, err = NewClient(node.Http2_builder{
				Concurrency: proto.Int32(1),
			}.Build(), p)
			assert.NoError(t, err)

			conn, err := p.Conn(context.TODO(), netapi.EmptyAddr)
			assert.NoError(t, err)

			src := <-ch

			// t.Log("new client", conn.RemoteAddr().String(), src, conn)

			return src, conn, func() {
				src.Close()
				conn.Close()
				p.Close()
				lis.Close()
			}, nil
		})
	})
}

func TestClient(t *testing.T) {
	lis, err := dialer.ListenContext(context.TODO(), "tcp", "127.0.0.1:8082")
	assert.NoError(t, err)
	defer lis.Close()

	lis = newServer(lis)

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				break
			}

			go func() {
				defer conn.Close()

				_, _ = io.Copy(io.MultiWriter(os.Stdout, conn), conn)
			}()
		}
	}()

	p, err := fixed.NewClient(node.Fixed_builder{
		Host: proto.String("127.0.0.1"),
		Port: proto.Int32(8082),
	}.Build(), nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	p, err = NewClient(node.Http2_builder{
		Concurrency: proto.Int32(1),
	}.Build(), p)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	conn, err := p.Conn(context.TODO(), netapi.EmptyAddr)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log("start write bbbb")
	_, err = conn.Write([]byte("bbbb"))
	if err != nil {
		t.Error(err)
		return
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Error(err)
		return
	}

	t.Log(string(buf[:n]))

	_, err = conn.Write([]byte("ccc"))
	if err != nil {
		t.Error(err)
	}

	n, err = conn.Read(buf)
	if err != nil {
		t.Error(err)
		return
	}

	t.Log(string(buf[:n]))
}

func TestAddr(t *testing.T) {
	qaddr := &addr{
		id:   9,
		addr: netapi.EmptyAddr.String(),
	}

	addr, err := netapi.ParseAddress("tcp", qaddr.String())
	assert.NoError(t, err)

	assert.Equal(t, addr.String(), qaddr.String())
	t.Log(qaddr, addr)
}

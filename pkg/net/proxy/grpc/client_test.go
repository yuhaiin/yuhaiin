package grpc

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/net/nettest"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

func TestConn(t *testing.T) {
	t.Run("test io", func(t *testing.T) {
		lis, err := nettest.NewLocalListener("tcp")
		assert.NoError(t, err)
		gs := NewGrpcNoServer(lis)

		server := make(chan net.Conn)
		go func() {
			conn, err := gs.Accept()
			assert.NoError(t, err)

			server <- conn
		}()

		host, portstr, err := net.SplitHostPort(lis.Addr().String())
		assert.NoError(t, err)

		port, err := strconv.ParseUint(portstr, 10, 16)
		assert.NoError(t, err)

		sp, err := fixed.NewClient(protocol.Fixed_builder{
			Host: proto.String(host),
			Port: proto.Int32(int32(port)),
		}.Build(), nil)
		assert.NoError(t, err)

		c, err := NewClient(protocol.Grpc_builder{
			Tls: &protocol.TlsConfig{},
		}.Build(), sp)
		assert.NoError(t, err)

		conn, err := c.Conn(context.TODO(), netapi.EmptyAddr)
		assert.NoError(t, err)

		src := <-server

		fmt.Println("conn", conn.RemoteAddr(), "src", src.RemoteAddr())

		testBasicIO(t, src, conn)

		defer func() {
			_ = conn.Close()
			_ = src.Close()
			_ = gs.Close()
			_ = lis.Close()
		}()
	})

	t.Run("test present timeout", func(t *testing.T) {
		lis, err := nettest.NewLocalListener("tcp")
		assert.NoError(t, err)
		gs := NewGrpcNoServer(lis)

		server := make(chan net.Conn)
		go func() {
			conn, err := gs.Accept()
			assert.NoError(t, err)

			server <- conn
		}()

		host, portstr, err := net.SplitHostPort(lis.Addr().String())
		assert.NoError(t, err)

		port, err := strconv.ParseUint(portstr, 10, 16)
		assert.NoError(t, err)

		sp, err := fixed.NewClient(protocol.Fixed_builder{
			Host: proto.String(host),
			Port: proto.Int32(int32(port)),
		}.Build(), nil)
		assert.NoError(t, err)

		c, err := NewClient(protocol.Grpc_builder{
			Tls: &protocol.TlsConfig{},
		}.Build(), sp)
		assert.NoError(t, err)

		conn, err := c.Conn(context.TODO(), netapi.EmptyAddr)
		assert.NoError(t, err)

		src := <-server

		fmt.Println("conn", conn.RemoteAddr(), "src", src.RemoteAddr())

		testPresentTimeout(t, conn, src)

		defer func() {
			_ = conn.Close()
			_ = src.Close()
			_ = gs.Close()
			_ = lis.Close()
		}()
	})

	t.Run("conn -> server", func(t *testing.T) {
		nettest.TestConn(t, func() (c1 net.Conn, c2 net.Conn, stop func(), err error) {
			lis, err := nettest.NewLocalListener("tcp")
			assert.NoError(t, err)
			gs := NewGrpcNoServer(lis)

			server := make(chan net.Conn)
			go func() {
				conn, err := gs.Accept()
				assert.NoError(t, err)

				server <- conn
			}()

			host, portstr, err := net.SplitHostPort(lis.Addr().String())
			assert.NoError(t, err)

			port, err := strconv.ParseUint(portstr, 10, 16)
			assert.NoError(t, err)

			sp, err := fixed.NewClient(protocol.Fixed_builder{
				Host: proto.String(host),
				Port: proto.Int32(int32(port)),
			}.Build(), nil)
			assert.NoError(t, err)

			c, err := NewClient(protocol.Grpc_builder{
				Tls: &protocol.TlsConfig{},
			}.Build(), sp)
			assert.NoError(t, err)

			conn, err := c.Conn(context.TODO(), netapi.EmptyAddr)
			assert.NoError(t, err)

			src := <-server

			fmt.Println("conn", conn.RemoteAddr(), "src", src.RemoteAddr())

			return conn, src, func() {
				conn.Close()
				src.Close()
				gs.Close()
				lis.Close()
			}, nil
		})
	})

	t.Run("server -> conn", func(t *testing.T) {
		nettest.TestConn(t, func() (c1 net.Conn, c2 net.Conn, stop func(), err error) {
			lis, err := nettest.NewLocalListener("tcp")
			assert.NoError(t, err)
			gs := NewGrpcNoServer(lis)

			server := make(chan net.Conn)
			go func() {
				conn, err := gs.Accept()
				assert.NoError(t, err)

				server <- conn
			}()

			host, portstr, err := net.SplitHostPort(lis.Addr().String())
			assert.NoError(t, err)

			port, err := strconv.ParseUint(portstr, 10, 16)
			assert.NoError(t, err)

			sp, err := fixed.NewClient(protocol.Fixed_builder{
				Host: proto.String(host),
				Port: proto.Int32(int32(port)),
			}.Build(), nil)
			assert.NoError(t, err)

			c, err := NewClient(protocol.Grpc_builder{
				Tls: &protocol.TlsConfig{},
			}.Build(), sp)
			assert.NoError(t, err)

			conn, err := c.Conn(context.TODO(), netapi.EmptyAddr)
			assert.NoError(t, err)

			src := <-server

			fmt.Println("conn", conn.RemoteAddr(), "src", src.RemoteAddr())

			return src, conn, func() {
				conn.Close()
				src.Close()
				gs.Close()
				lis.Close()
			}, nil
		})
	})
}

// testBasicIO tests that the data sent on c1 is properly received on c2.
func testBasicIO(t *testing.T, c1, c2 net.Conn) {
	want := make([]byte, 1<<20)
	rand.New(rand.NewSource(0)).Read(want)

	dataCh := make(chan []byte)
	go func() {
		rd := bytes.NewReader(want)
		if err := chunkedCopy(c1, rd); err != nil {
			t.Errorf("unexpected c1.Write error: %v", err)
		}
		if err := c1.Close(); err != nil {
			t.Errorf("unexpected c1.Close error: %v", err)
		}
	}()

	go func() {
		wr := new(bytes.Buffer)
		if err := chunkedCopy(wr, c2); err != nil {
			t.Errorf("unexpected c2.Read error: %v", err)
		}
		if err := c2.Close(); err != nil {
			t.Errorf("unexpected c2.Close error: %v", err)
		}
		dataCh <- wr.Bytes()
	}()

	if got := <-dataCh; !bytes.Equal(got, want) {
		t.Error("transmitted data differs", len(got), len(want))
	}
}

// chunkedCopy copies from r to w in fixed-width chunks to avoid
// causing a Write that exceeds the maximum packet size for packet-based
// connections like "unixpacket".
// We assume that the maximum packet size is at least 1024.
func chunkedCopy(w io.Writer, r io.Reader) error {
	b := make([]byte, 1024)
	_, err := io.CopyBuffer(struct{ io.Writer }{w}, struct{ io.Reader }{r}, b)
	return err
}

func TestServer(t *testing.T) {
	lis, err := nettest.NewLocalListener("tcp")
	assert.NoError(t, err)

	gs := grpc.NewServer()

	gs.RegisterService(&Stream_ServiceDesc, &mockStream{})
	go func() {
		err = gs.Serve(lis)
		assert.NoError(t, err)
	}()

	c, err := grpc.NewClient("yuhaiin-server",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			return net.Dial("tcp", lis.Addr().String())
		}))
	assert.NoError(t, err)

	sc := NewStreamClient(c)

	ss, err := sc.Conn(context.TODO())
	assert.NoError(t, err)

	err = ss.Send(&wrapperspb.BytesValue{Value: []byte("hello")})
	assert.NoError(t, err)

	err = ss.CloseSend()
	assert.NoError(t, err)

	err = ss.Send(&wrapperspb.BytesValue{Value: []byte("hello")})
	assert.Error(t, err)

	time.Sleep(time.Second)
}

type mockStream struct {
	UnimplementedStreamServer
}

func (m mockStream) Conn(req grpc.BidiStreamingServer[wrapperspb.BytesValue, wrapperspb.BytesValue]) error {
	for {
		data, err := req.Recv()
		if err != nil {
			fmt.Println(err)
			break
		}

		fmt.Println(string(data.Value))
	}

	return nil
}

// testPresentTimeout tests that a past deadline set while there are pending
// Read and Write operations immediately times out those operations.
func testPresentTimeout(t *testing.T, c1, c2 net.Conn) {

	aLongTimeAgo := time.Unix(233431200, 0)

	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(3)

	deadlineSet := make(chan bool, 1)
	wg.Go(func() {
		time.Sleep(100 * time.Millisecond)
		deadlineSet <- true
		c1.SetReadDeadline(aLongTimeAgo)
		c1.SetWriteDeadline(aLongTimeAgo)
	})

	wg.Go(func() {
		n, err := c1.Read(make([]byte, 1024))
		if n != 0 {
			t.Errorf("unexpected Read count: got %d, want 0", n)
		}
		checkForTimeoutError(t, err)
		if len(deadlineSet) == 0 {
			t.Error("Read timed out before deadline is set")
		}
	})

	wg.Go(func() {
		var err error
		for err == nil {
			_, err = c1.Write(make([]byte, 1024))
		}
		checkForTimeoutError(t, err)
		if len(deadlineSet) == 0 {
			t.Error("Write timed out before deadline is set")
		}
	})
}

// checkForTimeoutError checks that the error satisfies the Error interface
// and that Timeout returns true.
func checkForTimeoutError(t *testing.T, err error) {
	t.Helper()
	if nerr, ok := err.(net.Error); ok {
		if !nerr.Timeout() {
			if runtime.GOOS == "windows" && runtime.GOARCH == "arm64" && t.Name() == "TestTestConn/TCP/RacyRead" {
				t.Logf("ignoring known failure mode on windows/arm64; see https://go.dev/issue/52893")
			} else {
				t.Errorf("got error: %v, want err.Timeout() = true", nerr)
			}
		}
	} else {
		t.Errorf("got %T: %v, want net.Error", err, err)
	}
}
func TestAddr(t *testing.T) {
	qaddr := &addr{
		id: 1000,
	}

	addr, err := netapi.ParseAddress("tcp", qaddr.String())
	assert.NoError(t, err)

	assert.Equal(t, addr.String(), qaddr.String())
	t.Log(qaddr, addr)
}

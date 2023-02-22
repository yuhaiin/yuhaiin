package grpc

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

//go:generate protoc --go-grpc_out=. --go-grpc_opt=paths=source_relative chunk.proto

type Grpc struct {
	UnimplementedStreamServer
	connChan chan *conn
	id       id.IDGenerator

	listener net.Listener
	Server   *grpc.Server
}

func NewGrpc(lis net.Listener) *Grpc {
	g := NewGrpcNoServer()
	g.listener = lis
	go g.Server.Serve(lis)
	return g
}

func NewGrpcNoServer() *Grpc {

	s := grpc.NewServer()

	g := &Grpc{
		connChan: make(chan *conn, 30),
		Server:   s,
	}

	s.RegisterService(&Stream_ServiceDesc, g)

	return g
}

func (g *Grpc) Addr() net.Addr {
	if g.listener != nil {
		return g.listener.Addr()
	}

	return proxy.EmptyAddr
}

func (g *Grpc) Close() error {
	g.Server.Stop()

	var err error
	if g.listener != nil {
		err = g.listener.Close()
	}

	return err
}

func (g *Grpc) Accept() (net.Conn, error) {
	conn, ok := <-g.connChan
	if !ok {
		return nil, net.ErrClosed
	}

	return conn, nil
}

func (s *Grpc) Conn(con Stream_ConnServer) error {
	ctx, cancel := context.WithCancel(con.Context())
	s.connChan <- &conn{
		raw:   con,
		raddr: &addr{s.id.Generate()},
		laddr: s.Addr(),
		close: cancel,
	}

	<-ctx.Done()

	return nil
}

type stream_conn interface {
	Send(*wrapperspb.BytesValue) error
	Recv() (*wrapperspb.BytesValue, error)
}

var _ net.Conn = (*conn)(nil)

type conn struct {
	raw stream_conn

	buf  *bytes.Buffer
	rmux sync.Mutex

	raddr net.Addr
	laddr net.Addr

	closed bool
	mu     sync.Mutex
	close  context.CancelFunc

	deadline *time.Timer
}

func (c *conn) Read(b []byte) (int, error) {
	c.rmux.Lock()
	defer c.rmux.Unlock()

	if c.buf != nil && c.buf.Len() > 0 {
		return c.buf.Read(b)
	}

	data, err := c.raw.Recv()
	if err != nil {
		return 0, err
	}
	c.buf = bytes.NewBuffer(data.Value)

	return c.buf.Read(b)
}

func (c *conn) Write(b []byte) (int, error) {
	if err := c.raw.Send(&wrapperspb.BytesValue{Value: b}); err != nil {
		return 0, err
	}

	return len(b), nil
}

func (c *conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.close()
	c.closed = true
	return nil
}
func (c *conn) LocalAddr() net.Addr  { return c.laddr }
func (c *conn) RemoteAddr() net.Addr { return c.raddr }

func (c *conn) SetDeadline(t time.Time) error {
	if c.deadline == nil {
		if !t.IsZero() {
			c.deadline = time.AfterFunc(t.Sub(time.Now()), func() { c.Close() })
		}
		return nil
	}

	if t.IsZero() {
		c.deadline.Stop()
	} else {
		c.deadline.Reset(t.Sub(time.Now()))
	}

	return nil
}

func (c *conn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *conn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

type addr struct {
	id uint64
}

func (addr) Network() string  { return "grpc" }
func (a addr) String() string { return fmt.Sprintf("grpc://%d", a.id) }

type client struct {
	proxy.EmptyDispatch
	dialer proxy.Proxy

	rawConn    net.Conn
	clientConn *grpc.ClientConn
	client     StreamClient

	tlsConfig *tls.Config

	count     *atomic.Int64
	stopTimer *time.Timer
	mu        sync.Mutex
}

func New(config *protocol.Protocol_Grpc) protocol.WrapProxy {
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		return &client{
			dialer:    p,
			count:     &atomic.Int64{},
			tlsConfig: protocol.ParseTLSConfig(config.Grpc.Tls),
		}, nil
	}
}

func (c *client) initClient() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.clientConn != nil {
		c.clientCountAdd()
		return nil
	}

	rawConn, err := c.dialer.Conn(proxy.EmptyAddr)
	if err != nil {
		return err
	}

	var tlsOption grpc.DialOption
	if c.tlsConfig == nil {
		tlsOption = grpc.WithInsecure()
	} else {
		tlsOption = grpc.WithTransportCredentials(credentials.NewTLS(c.tlsConfig))
	}

	clientConn, err := grpc.Dial("",
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  500 * time.Millisecond,
				Multiplier: 1.5,
				Jitter:     0.2,
				MaxDelay:   19 * time.Second,
			},
			MinConnectTimeout: 5 * time.Second,
		}),
		grpc.WithInitialWindowSize(65536),
		tlsOption,
		grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) { return rawConn, nil }))
	if err != nil {
		rawConn.Close()
		return err
	}

	c.rawConn = rawConn
	c.clientConn = clientConn
	c.client = NewStreamClient(clientConn)
	c.clientCountAdd()

	return nil
}

func (c *client) clientCountAdd() {
	if c.count.Add(1) == 1 && c.stopTimer != nil {
		c.stopTimer.Stop()
	}
}

func (c *client) clientCountSub() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.count.Add(-1) != 0 {
		return
	}

	if c.stopTimer == nil {
		c.stopTimer = time.AfterFunc(time.Minute, c.close)
	} else {
		c.stopTimer.Reset(time.Minute)
	}
}

func (c *client) reconnect() error {
	c.close()
	return c.initClient()
}

func (c *client) close() {
	c.mu.Lock()
	if c.clientConn != nil {
		c.clientConn.Close()
		c.rawConn.Close()
		c.clientConn = nil
		c.client = nil
		c.rawConn = nil
	}
	c.mu.Unlock()
}

func (c *client) Conn(addr proxy.Address) (net.Conn, error) {
	if err := c.initClient(); err != nil {
		return nil, err
	}
	var retried bool

_retry:
	ctx, cancel := context.WithCancel(context.TODO())
	con, err := c.client.Conn(ctx)
	if err != nil {
		cancel()
		if !retried {
			if er := c.reconnect(); er != nil {
				return nil, er
			}
			retried = true
			goto _retry
		}
		return nil, err
	}

	return &conn{
		raw:   con,
		laddr: c.rawConn.LocalAddr(),
		close: func() {
			cancel()
			con.CloseSend()
			c.clientCountSub()
		},
		raddr: c.rawConn.RemoteAddr(),
	}, nil
}

func (c *client) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	return c.dialer.PacketConn(addr)
}

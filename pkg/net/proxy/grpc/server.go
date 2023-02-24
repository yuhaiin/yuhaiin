package grpc

import (
	context "context"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	grpc "google.golang.org/grpc"
)

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

type addr struct {
	id uint64
}

func (addr) Network() string  { return "grpc" }
func (a addr) String() string { return fmt.Sprintf("grpc://%d", a.id) }

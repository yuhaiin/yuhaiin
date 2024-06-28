package grpc

import (
	context "context"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	grpc "google.golang.org/grpc"
)

type Grpc struct {
	UnimplementedStreamServer

	listener net.Listener
	connChan chan *conn
	Server   *grpc.Server
	id       id.IDGenerator
}

func init() {
	listener.RegisterTransport(NewServer)
}

func NewServer(c *listener.Transport_Grpc) func(netapi.Listener) (netapi.Listener, error) {
	return func(ii netapi.Listener) (netapi.Listener, error) {
		lis, err := ii.Stream(context.TODO())
		if err != nil {
			return nil, err
		}

		return netapi.PatchStream(NewGrpcNoServer(lis), ii), nil
	}
}

func NewGrpcNoServer(lis net.Listener) *Grpc {
	s := grpc.NewServer()

	g := &Grpc{
		connChan: make(chan *conn, 30),
		Server:   s,
		listener: lis,
	}

	s.RegisterService(&Stream_ServiceDesc, g)

	if lis != nil {
		go log.IfErr("grpc serve", func() error { return s.Serve(lis) })
	}

	return g
}

func (g *Grpc) Addr() net.Addr {
	if g.listener != nil {
		return g.listener.Addr()
	}

	return netapi.EmptyAddr
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
	s.connChan <- newConn(con, s.Addr(), &addr{s.id.Generate()}, cancel)
	<-ctx.Done()
	return nil
}

type addr struct {
	id uint64
}

func (addr) Network() string  { return "tcp" }
func (a addr) String() string { return fmt.Sprintf("grpc://%d", a.id) }

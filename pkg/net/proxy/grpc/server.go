package grpc

import (
	context "context"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

type Grpc struct {
	UnimplementedStreamServer

	listener net.Listener
	connChan chan *pipe.Conn
	Server   *grpc.Server
	id       id.IDGenerator
}

func init() {
	register.RegisterTransport(NewServer)
}

func NewServer(c *listener.Grpc, ii netapi.Listener) (netapi.Listener, error) {
	return netapi.NewListener(NewGrpcNoServer(ii), ii), nil
}

func NewGrpcNoServer(lis net.Listener) *Grpc {
	s := grpc.NewServer()

	g := &Grpc{
		connChan: make(chan *pipe.Conn, 30),
		Server:   s,
		listener: lis,
	}

	RegisterStreamServer(s, g)

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

func (s *Grpc) Conn(con grpc.BidiStreamingServer[wrapperspb.BytesValue, wrapperspb.BytesValue]) error {
	ctx, cancel := context.WithCancel(con.Context())
	c1, c2 := pipe.Pipe()

	go func() {
		defer func() {
			if err := c1.CloseWrite(); err != nil {
				log.Error("grpc server conn close write failed", "err", err)
			}
		}()
		for {
			data, err := con.Recv()
			if err != nil {
				if err != io.EOF {
					s, ok := status.FromError(err)
					if !ok || s.Code() != codes.Canceled {
						log.Error("grpc server conn recv failed", "err", err)
					}
				}
				return
			}

			_, err = c1.Write(data.Value)
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer cancel()
		defer c1.Close()
		for {
			buf := make([]byte, 1024)
			n, err := c1.Read(buf)
			if err != nil {
				return
			}

			err = con.Send(&wrapperspb.BytesValue{Value: buf[:n]})
			if err != nil {
				return
			}
		}
	}()

	c2.SetLocalAddr(&addr{s.id.Generate()})
	c2.SetRemoteAddr(s.Addr())

	s.connChan <- c2
	select {
	case <-con.Context().Done():
	case <-ctx.Done():
	}
	return nil
}

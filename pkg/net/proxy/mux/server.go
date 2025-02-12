package mux

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/libp2p/go-yamux/v5"
)

type MuxServer struct {
	net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	connChan chan net.Conn
}

func init() {
	register.RegisterTransport(NewServer)
}

func NewServer(config *listener.Mux, ii netapi.Listener) (netapi.Listener, error) {
	lis, err := ii.Stream(context.TODO())
	if err != nil {
		return nil, err
	}

	return netapi.NewListener(newServer(lis), ii), nil
}

func newServer(lis net.Listener) *MuxServer {
	ctx, cancel := context.WithCancel(context.TODO())
	mux := &MuxServer{
		Listener: lis,
		ctx:      ctx,
		cancel:   cancel,
		connChan: make(chan net.Conn, 1024),
	}

	go log.IfErr("yamux server", mux.Run, net.ErrClosed)

	return mux
}

func (m *MuxServer) Accept() (net.Conn, error) {
	select {
	case conn := <-m.connChan:
		return conn, nil
	case <-m.ctx.Done():
		return nil, m.ctx.Err()
	}
}

func (m *MuxServer) Run() error {
	for {
		conn, err := m.Listener.Accept()
		if err != nil {
			return err
		}

		go func() {
			defer conn.Close()

			session, err := yamux.Server(conn, config, nil)
			if err != nil {
				log.Error("yamux server error", "err", err)
				return
			}
			defer session.Close()

			for {
				c, err := session.AcceptStream()
				if err != nil {
					if !errors.Is(err, io.EOF) {
						log.Error("yamux accept error", "err", err)
					}
					return
				}

				select {
				case <-m.ctx.Done():
					return
				case m.connChan <- &muxConn{MuxConn: c}:
				}
			}
		}()
	}
}

func (m *MuxServer) Close() error {
	m.cancel()
	return m.Listener.Close()
}

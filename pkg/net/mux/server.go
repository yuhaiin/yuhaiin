package mux

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/libp2p/go-yamux/v4"
)

type MuxServer struct {
	net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	connChan chan net.Conn
}

func NewServer(lis net.Listener) *MuxServer {
	ctx, cancel := context.WithCancel(context.TODO())
	mux := &MuxServer{
		Listener: lis,
		ctx:      ctx,
		cancel:   cancel,
		connChan: make(chan net.Conn, 1024),
	}

	go func() {
		if err := mux.Run(); err != nil {
			log.Error("yamux server error", "err", err)
		}
	}()

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

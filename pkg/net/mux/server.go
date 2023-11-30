package mux

import (
	"errors"
	"io"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/libp2p/go-yamux/v4"
)

type MuxServer struct {
	net.Listener
	mu       sync.RWMutex
	closed   bool
	connChan chan net.Conn
}

func NewServer(lis net.Listener) *MuxServer {
	mux := &MuxServer{
		Listener: lis,
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
	conn, ok := <-m.connChan
	if !ok {
		return nil, net.ErrClosed
	}

	return conn, nil
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

				m.mu.RLock()
				if m.closed {
					return
				}

				m.connChan <- &muxConn{c}
				m.mu.RUnlock()
			}
		}()
	}
}

func (m *MuxServer) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true
	close(m.connChan)

	return m.Listener.Close()
}

package websocket

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	websocket "github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket/x"
)

type Server struct {
	net.Listener
	server   *http.Server
	connChan chan net.Conn
	closed   bool
	mu       sync.RWMutex
}

func NewServer(lis net.Listener) *Server {
	s := &Server{
		Listener: lis,
		connChan: make(chan net.Conn, 20),
	}
	s.server = &http.Server{Handler: s}

	go func() {
		defer s.Close()
		if err := s.server.Serve(lis); err != nil {
			log.Error("websocket serve failed:", "err", err)
		}
	}()

	return s
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}

	err := s.server.Close()
	if er := s.Listener.Close(); er != nil {
		err = errors.Join(err, er)
	}
	close(s.connChan)
	s.closed = true
	return err
}

func (s *Server) Accept() (net.Conn, error) {
	conn, ok := <-s.connChan
	if !ok {
		return nil, net.ErrClosed
	}

	return conn, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var earlyData [][]byte
	wsconn, err := websocket.NewServerConn(w, req, func(r *websocket.Request) error {
		if r.Request.Header.Get("early_data") == "base64" {
			data, err := base64.RawStdEncoding.DecodeString(r.SecWebSocketKey)
			if err != nil {
				return err
			}

			earlyData = append(earlyData, data)

			r.Header = http.Header{}
			r.Header.Add("early_data", "true")
		}

		return nil
	})
	if err != nil {
		log.Error("new websocket server conn failed", slog.Any("from", req.RemoteAddr), slog.Any("err", err))
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return
	}

	s.connChan <- netapi.NewPrefixBytesConn(wsconn, earlyData...)
}

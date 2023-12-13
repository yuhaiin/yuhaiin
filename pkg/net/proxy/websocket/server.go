package websocket

import (
	"context"
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
	closeCtx context.Context
	close    context.CancelFunc
	mu       sync.RWMutex

	closed bool
	once   sync.Once
}

func NewServer(lis net.Listener) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		Listener: lis,
		connChan: make(chan net.Conn, 20),
		closeCtx: ctx,
		close:    cancel,
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
	var err error
	s.once.Do(func() {
		s.close()
		err = s.server.Close()
		if er := s.Listener.Close(); er != nil {
			err = errors.Join(err, er)
		}

		log.Info("start close websocket conn chan")
		s.mu.Lock()
		defer s.mu.Unlock()
		s.closed = true
		close(s.connChan)
		log.Info("closed websocket conn chan")
	})

	return err
}

func (s *Server) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-s.connChan:
		if !ok {
			return nil, net.ErrClosed
		}

		return conn, nil

	case <-s.closeCtx.Done():
		return nil, net.ErrClosed
	}
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

	select {
	case <-s.closeCtx.Done():
		_ = wsconn.Close()
		return
	default:
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		_ = wsconn.Close()
		return
	}

	s.connChan <- netapi.NewPrefixBytesConn(wsconn, earlyData...)
}

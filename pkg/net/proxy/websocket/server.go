package websocket

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
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
		s.server.Serve(lis)
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
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return
	}

	var earlyData *bytes.Buffer
	wsconn, err := websocket.NewServerConn(w, req, func(r *websocket.Request) error {
		if r.Request.Header.Get("early_data") == "base64" {
			data, err := base64.RawStdEncoding.DecodeString(r.SecWebSocketKey)
			if err != nil {
				return err
			}

			earlyData = bytes.NewBuffer(data)

			r.Header = http.Header{}
			r.Header.Add("early_data", "true")
		}

		return nil
	})
	if err != nil {
		log.Errorln("new websocket server conn failed:", err)
		return
	}

	if earlyData == nil {
		s.connChan <- wsconn
	} else {
		s.connChan <- &Conn{wsconn, earlyData}
	}
}

type Conn struct {
	*websocket.Conn
	buf *bytes.Buffer
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.buf != nil {
		if c.buf.Len() > 0 {
			return c.buf.Read(b)
		}
		c.buf = nil
	}

	return c.Conn.Read(b)
}

package websocket

import (
	"bufio"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	_ "unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"golang.org/x/net/websocket"
)

//go:linkname newServerConn golang.org/x/net/websocket.newServerConn
func newServerConn(rwc io.ReadWriteCloser, buf *bufio.ReadWriter, req *http.Request, config *websocket.Config, handshake func(*websocket.Config, *http.Request) error) (conn *websocket.Conn, err error)

type Server struct {
	net.Listener
	server   *http.Server
	connChan chan *Connection
	closed   bool
	lock     sync.RWMutex
}

func NewServer(lis net.Listener) *Server {
	s := &Server{
		Listener: lis,
		connChan: make(chan *Connection, 20),
	}
	s.server = &http.Server{Handler: s}

	go func() {
		defer s.Close()
		s.server.Serve(lis)
	}()

	return s
}

func (s *Server) Close() error {
	s.lock.Lock()
	defer s.lock.Unlock()
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
	s.lock.RLock()
	defer s.lock.RUnlock()

	if s.closed {
		return
	}

	if strings.ToLower(req.Header.Get("Upgrade")) != "websocket" ||
		!strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade") {
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><style>body { max-width:400px; margin: 0 auto; }</style><title>A8.net</title></head><body>あなたのIPアドレスは %q<br/>A8スタッフブログ <a href="https://a8pr.jp">https://a8pr.jp</a></body></html>`, html.EscapeString(req.Header.Get("Cf-Connecting-Ip")))
		return
	}

	conn, buf, err := w.(http.Hijacker).Hijack()
	if err != nil {
		log.Errorln("hijack failed:", err)
		return
	}

	wsconn, err := newServerConn(conn, buf, req, &websocket.Config{}, nil)
	if err != nil {
		log.Errorln("new websocket server conn failed:", err)
		return
	}

	s.connChan <- &Connection{wsconn, conn}
}

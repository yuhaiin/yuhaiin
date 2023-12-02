package http2

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type Server struct {
	mu       sync.Mutex
	server   *http.Server
	listener net.Listener
	connChan chan net.Conn
	id       id.IDGenerator
	closed   bool
}

func NewServer(lis net.Listener) *Server {
	h := &Server{
		listener: lis,
		connChan: make(chan net.Conn, 20),
	}
	h2s := &http2.Server{
		IdleTimeout: time.Minute,
	}

	h.server = &http.Server{
		Handler:           h2c.NewHandler(h, h2s),
		ReadHeaderTimeout: time.Second * 4,
	}

	go func() {
		defer h.Close()
		if err := h.server.Serve(lis); err != nil {
			log.Error("http2 serve failed:", "err", err)
		}
	}()

	return h
}

func (h *Server) Accept() (net.Conn, error) {
	conn, ok := <-h.connChan
	if !ok {
		return nil, net.ErrClosed
	}

	return conn, nil
}

func (g *Server) Addr() net.Addr {
	if g.listener != nil {
		return g.listener.Addr()
	}

	return netapi.EmptyAddr
}

func (h *Server) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}

	err := h.server.Close()
	if er := h.listener.Close(); er != nil {
		err = errors.Join(err, er)
	}
	close(h.connChan)
	h.closed = true
	return err
}

func (h *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	fw := newFlushWriter(w)
	h.connChan <- &http2Conn{
		fw,
		r.Body,
		h.Addr(),
		&addr{r.RemoteAddr, h.id.Generate()},
		nil,
	}
	<-r.Context().Done()
	fw.Close()
}

var _ net.Conn = (*http2Conn)(nil)

type flushWriter struct {
	w      io.Writer
	flush  http.Flusher
	mu     sync.Mutex
	closed bool
}

func newFlushWriter(w io.Writer) *flushWriter {
	fw := &flushWriter{
		w: w,
	}

	if f, ok := w.(http.Flusher); ok {
		fw.flush = f
	}

	return fw
}

func (fw *flushWriter) Write(p []byte) (n int, err error) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if fw.closed {
		return 0, net.ErrClosed
	}

	n, err = fw.w.Write(p)
	if err == nil && fw.flush != nil {
		fw.flush.Flush()
	}

	return
}

func (fw *flushWriter) Close() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	fw.closed = true
	return nil
}

type http2Conn struct {
	w io.WriteCloser
	r io.ReadCloser

	localAddr  net.Addr
	remoteAddr net.Addr

	deadline *time.Timer
}

func (h *http2Conn) Read(b []byte) (int, error)  { return h.r.Read(b) }
func (h *http2Conn) Write(b []byte) (int, error) { return h.w.Write(b) }
func (h *http2Conn) Close() error {
	h.w.Close()
	return h.r.Close()
}
func (h *http2Conn) LocalAddr() net.Addr  { return h.localAddr }
func (h *http2Conn) RemoteAddr() net.Addr { return h.remoteAddr }

func (c *http2Conn) SetDeadline(t time.Time) error {
	if c.deadline == nil {
		if !t.IsZero() {
			c.deadline = time.AfterFunc(time.Until(t), func() { c.Close() })
		}
		return nil
	}

	if t.IsZero() {
		c.deadline.Stop()
	} else {
		c.deadline.Reset(time.Until(t))
	}

	return nil
}
func (c *http2Conn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *http2Conn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

type addr struct {
	addr string
	id   uint64
}

func (addr) Network() string  { return "http2" }
func (a addr) String() string { return fmt.Sprintf("http2://%s-%d", a.addr, a.id) }

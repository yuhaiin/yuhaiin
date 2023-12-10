package http2

import (
	"context"
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
)

type Server struct {
	mu        sync.Mutex
	listener  net.Listener
	connChan  chan net.Conn
	id        id.IDGenerator
	closedCtx context.Context
	close     context.CancelFunc
}

func NewServer(lis net.Listener) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	h := &Server{
		listener:  lis,
		connChan:  make(chan net.Conn, 20),
		closedCtx: ctx,
		close:     cancel,
	}

	go func() {
		defer h.Close()

		for {
			conn, err := lis.Accept()
			if err != nil {
				log.Error("accept failed:", "err", err)
				return
			}

			go func() {
				defer conn.Close()
				(&http2.Server{
					IdleTimeout: time.Minute,
				}).ServeConn(conn, &http2.ServeConnOpts{
					Handler: h,
					Context: h.closedCtx,
				})
			}()
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

	select {
	case <-h.closedCtx.Done():
		return nil
	default:
	}

	err := h.listener.Close()
	close(h.connChan)
	h.close()
	return err
}

func (h *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	fw := newFlushWriter(w)

	conn := &http2Conn{
		fw,
		r.Body,
		h.Addr(),
		&addr{r.RemoteAddr, h.id.Generate()},
		nil,
	}

	select {
	case h.connChan <- conn:
	case <-h.closedCtx.Done():
	}

	select {
	case <-r.Context().Done():
	case <-h.closedCtx.Done():
	}

	_ = conn.Close()
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

func (addr) Network() string  { return "tcp" }
func (a addr) String() string { return fmt.Sprintf("http2://%s-%d", a.addr, a.id) }

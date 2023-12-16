package http2

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"golang.org/x/net/http2"
)

type Server struct {
	mu        sync.RWMutex
	listener  net.Listener
	id        id.IDGenerator
	closedCtx context.Context
	close     context.CancelFunc

	connChan chan net.Conn
	closed   bool

	conns syncmap.SyncMap[string, net.Conn]

	once sync.Once
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
		defer cancel()

		for {
			conn, err := lis.Accept()
			if err != nil {
				log.Error("accept failed:", "err", err)
				return
			}

			go func() {
				key := conn.RemoteAddr().String() + conn.LocalAddr().String()
				h.conns.Store(key, conn)

				defer func() {
					h.conns.Delete(key)
					conn.Close()
				}()

				(&http2.Server{
					MaxConcurrentStreams: math.MaxUint32,
					IdleTimeout:          time.Minute,
					MaxReadFrameSize:     pool.DefaultSize,
					NewWriteScheduler: func() http2.WriteScheduler {
						return http2.NewRandomWriteScheduler()
					},
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
	select {
	case conn, ok := <-h.connChan:
		if !ok {
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-h.closedCtx.Done():
		return nil, net.ErrClosed
	}
}

func (g *Server) Addr() net.Addr {
	if g.listener != nil {
		return g.listener.Addr()
	}

	return netapi.EmptyAddr
}

func (h *Server) Close() error {
	if h.closed {
		return nil
	}

	var err error
	h.once.Do(func() {
		h.close()
		log.Info("start close http2 underlying listener")
		err = h.listener.Close()
		log.Info("closed http2 underlying listener")

		h.conns.Range(func(key string, conn net.Conn) bool {
			_ = conn.Close()
			return true
		})

		log.Info("start close http2 conn chan")
		h.mu.Lock()
		h.closed = true
		close(h.connChan)
		h.mu.Unlock()
		log.Info("closed http2 conn chan")
	})

	return err
}

func (h *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	fw := newFlushWriter(w)

	conn := &http2Conn{
		true,
		nil,
		fw,
		r.Body,
		h.Addr(),
		&addr{r.RemoteAddr, h.id.Generate()},
		nil,
	}
	defer conn.Close()

	select {
	case <-r.Context().Done():
		return
	case <-h.closedCtx.Done():
		return
	default:
	}

	h.mu.RLock()
	if h.closed {
		h.mu.RUnlock()
		return
	}
	h.connChan <- conn
	h.mu.RUnlock()

	select {
	case <-r.Context().Done():
	case <-h.closedCtx.Done():
	}
}

var _ net.Conn = (*http2Conn)(nil)

type flushWriter struct {
	w      io.Writer
	flush  http.Flusher
	mu     sync.RWMutex
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
	fw.mu.RLock()
	if fw.closed {
		return 0, io.EOF
	}

	n, err = fw.w.Write(p)
	if err == nil && fw.flush != nil {
		fw.flush.Flush()
	}
	fw.mu.RUnlock()

	return
}

func (fw *flushWriter) Close() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	fw.closed = true
	return nil
}

type http2Conn struct {
	server bool

	piper *io.PipeReader

	pipew io.WriteCloser
	r     io.ReadCloser

	localAddr  net.Addr
	remoteAddr net.Addr

	deadline *time.Timer
}

func (h *http2Conn) Read(b []byte) (int, error) {
	n, err := h.r.Read(b)
	if err != nil {
		if he, ok := err.(http2.StreamError); h.server && ok {
			// closed client, will send RSTStreamFrame
			// see https://github.com/golang/net/blob/577e44a5cee023bd639dd2dcc4008644bcb71472/http2/server.go#L1615
			if he.Code == http2.ErrCodeCancel || he.Code == http2.ErrCodeNo {
				err = io.EOF
			}
		}
	}

	return n, err
}

func (h *http2Conn) Write(b []byte) (int, error) { return h.pipew.Write(b) }
func (h *http2Conn) Close() error {
	if h.piper != nil {
		h.piper.CloseWithError(io.EOF)
	}

	h.pipew.Close()

	if !h.server {
		return h.r.Close()
	}

	return nil
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

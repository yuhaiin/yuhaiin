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
	"github.com/Asutorufa/yuhaiin/pkg/net/deadline"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"golang.org/x/net/http2"
)

type Server struct {
	listener  net.Listener
	id        id.IDGenerator
	closedCtx context.Context
	close     context.CancelFunc

	connChan chan net.Conn

	conns syncmap.SyncMap[string, net.Conn]
}

func init() {
	listener.RegisterTransport(NewServer)
}

func NewServer(c *listener.Transport_Http2) func(netapi.Listener) (netapi.Listener, error) {
	return func(ii netapi.Listener) (netapi.Listener, error) {
		lis, err := ii.Stream(context.TODO())
		if err != nil {
			return nil, err
		}
		return netapi.ListenWrap(newServer(lis), ii), nil
	}
}

func newServer(lis net.Listener) *Server {
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
	case conn := <-h.connChan:
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
	var err error
	h.close()
	log.Info("start close http2 underlying listener")
	err = h.listener.Close()
	log.Info("closed http2 underlying listener")

	h.conns.Range(func(key string, conn net.Conn) bool {
		_ = conn.Close()
		return true
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
		deadline.NewPipe(
			// deadline.WithReadClose(func() {
			// _ = r.Body.Close()
			// }),
			deadline.WithWriteClose(func() {
				_ = fw.Close()
			}),
		),
	}
	defer conn.Close()

	select {
	case <-r.Context().Done():
		return
	case <-h.closedCtx.Done():
		return
	case h.connChan <- conn:
	}

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

	deadline *deadline.PipeDeadline
}

func (h *http2Conn) Read(b []byte) (int, error) {
	select {
	case <-h.deadline.ReadContext().Done():
		return 0, h.deadline.ReadContext().Err()
	default:
	}

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

func (h *http2Conn) Write(b []byte) (int, error) {
	select {
	case <-h.deadline.WriteContext().Done():
		return 0, h.deadline.WriteContext().Err()
	default:
	}

	return h.pipew.Write(b)
}

func (h *http2Conn) Close() error {
	if h.piper != nil {
		h.piper.CloseWithError(io.EOF)
	}

	h.pipew.Close()

	if !h.server {
		return h.r.Close()
	}

	_ = h.deadline.Close()

	return nil
}

func (h *http2Conn) LocalAddr() net.Addr  { return h.localAddr }
func (h *http2Conn) RemoteAddr() net.Addr { return h.remoteAddr }

func (c *http2Conn) SetDeadline(t time.Time) error {
	c.deadline.SetDeadline(t)
	return nil
}

func (c *http2Conn) SetReadDeadline(t time.Time) error {
	c.deadline.SetReadDeadline(t)
	return nil
}

func (c *http2Conn) SetWriteDeadline(t time.Time) error {
	c.deadline.SetWriteDeadline(t)
	return nil
}

type addr struct {
	addr string
	id   uint64
}

func (addr) Network() string  { return "tcp" }
func (a addr) String() string { return fmt.Sprintf("http2://%s-%d", a.addr, a.id) }

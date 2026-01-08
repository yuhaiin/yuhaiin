package http2

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/net/relay"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"golang.org/x/net/http2"
)

type Server struct {
	listener  net.Listener
	closedCtx context.Context
	close     context.CancelFunc

	connChan chan net.Conn

	conns syncmap.SyncMap[string, net.Conn]
	id    id.IDGenerator
}

func init() {
	register.RegisterTransport(NewServer)
}

func NewServer(c *config.Http2, ii netapi.Listener) (netapi.Listener, error) {
	return netapi.NewListener(newServer(ii), ii), nil
}

type warpConn struct {
	net.Conn
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
		defer func() {
			if err := h.Close(); err != nil {
				log.Error("close server failed", "err", err)
			}
		}()
		defer cancel()

		erl := netapi.NewErrCountListener(lis, 10)
		for {
			conn, err := erl.Accept()
			if err != nil {
				log.Error("accept failed", "err", err)
				return
			}

			// see https://github.com/golang/net/blob/163d83654d4d78be90251b9bf05aa502b6f7e79d/http2/server.go#L500
			// it will check is [*tls.Conn], if we don't tls handshake here, the http2 will return error
			conn = warpConn{conn}

			go func() {
				key := conn.RemoteAddr().String() + conn.LocalAddr().String()
				h.conns.Store(key, conn)

				defer func() {
					h.conns.Delete(key)
					_ = conn.Close()
				}()

				h2s := &http2.Server{
					MaxConcurrentStreams: math.MaxUint32,
					IdleTimeout:          time.Minute,
					MaxReadFrameSize:     pool.DefaultSize,
					NewWriteScheduler:    http2.NewRandomWriteScheduler,
				}

				h2Opt := &http2.ServeConnOpts{
					Handler:    h,
					Context:    h.closedCtx,
					BaseConfig: new(http.Server),
				}

				h2s.ServeConn(conn, h2Opt)
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
	select {
	case <-h.closedCtx.Done():
		return nil
	default:
		h.close()
	}

	err := h.listener.Close()
	for _, v := range h.conns.Range {
		_ = v.Close()
	}

	return err
}

type flusher struct {
	w http.ResponseWriter
}

func (f *flusher) Write(b []byte) (int, error) {
	n, err := f.w.Write(b)
	if f, ok := f.w.(http.Flusher); ok {
		f.Flush()
	}
	return n, err
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	c1, c2 := pipe.Pipe()

	c2.SetLocalAddr(s.Addr())
	c2.SetRemoteAddr(&addr{r.RemoteAddr, s.id.Generate()})

	select {
	case <-r.Context().Done():
		return
	case <-s.closedCtx.Done():
		return
	case s.connChan <- c2:
	}

	go func() {
		_, err := relay.Copy(c1, &bodyReader{r.Body})
		if err != nil && err != io.EOF && err != io.ErrClosedPipe &&
			// https://github.com/golang/net/blob/163d83654d4d78be90251b9bf05aa502b6f7e79d/http2/server.go#L69
			err.Error() != "client disconnected" {
			log.Error("relay failed", "err", err)
		}
		_ = c1.Close()
	}()

	flusher := &flusher{
		w: w,
	}

	_, err := relay.Copy(flusher, c1)
	if err != nil && err != io.EOF && err != io.ErrClosedPipe {
		log.Error("flush data to client failed", "err", err)
	}
}

type addr struct {
	addr string
	id   uint64
}

func (addr) Network() string  { return "tcp" }
func (a addr) String() string { return fmt.Sprintf("http2.h-%d-2%v", a.id, a.addr) }

type bodyReader struct {
	io.ReadCloser
}

func NewBodyReader(r io.ReadCloser) io.ReadCloser {
	return &bodyReader{r}
}

func (r *bodyReader) Read(b []byte) (int, error) {
	n, err := r.ReadCloser.Read(b)
	if err != nil {
		if he, ok := err.(http2.StreamError); ok {
			// closed client, will send RSTStreamFrame
			// see https://github.com/golang/net/blob/577e44a5cee023bd639dd2dcc4008644bcb71472/http2/server.go#L1615
			if he.Code == http2.ErrCodeCancel || he.Code == http2.ErrCodeNo {
				err = io.EOF
			}
		}
	}

	return n, err
}

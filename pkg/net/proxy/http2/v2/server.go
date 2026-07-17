package http2

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/net/relay"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
)

type Server struct {
	listener net.Listener
	http     *http.Server

	closedCtx context.Context
	close     context.CancelFunc
	closeOnce sync.Once
	closeErr  error

	connChan chan net.Conn
	id       id.IDGenerator
}

type ServerConfig struct{}

func NewServer(_ ServerConfig, ii netapi.Listener) (netapi.Listener, error) {
	return netapi.NewListener(newServer(ii), ii), nil
}

func newServer(lis net.Listener) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	// This listener accepts only HTTP/2 prior knowledge over plaintext.
	// Leaving HTTP/1 and TLS HTTP/2 unset is intentional.
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)

	h := &Server{
		listener:  lis,
		closedCtx: ctx,
		close:     cancel,
		connChan:  make(chan net.Conn, 20),
	}

	h.http = &http.Server{
		Handler:   h,
		Protocols: protocols,
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams: int(^uint(0) >> 1),
			MaxReadFrameSize:     pool.DefaultSize,
		},
		BaseContext: func(net.Listener) context.Context {
			return h.closedCtx
		},
		IdleTimeout: time.Minute,
	}

	go func() {
		err := h.http.Serve(lis)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !strings.Contains(err.Error(), "use of closed network connection") {
			select {
			case <-h.closedCtx.Done():
				return
			default:
			}
			log.Error("serve http2.v2 failed", "err", err)
		}
		h.close()
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

func (h *Server) Addr() net.Addr {
	if h.listener != nil {
		return h.listener.Addr()
	}
	return netapi.EmptyAddr
}

func (h *Server) Close() error {
	h.closeOnce.Do(func() {
		h.close()
		h.closeErr = h.http.Close()
	})
	return h.closeErr
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	c1, c2 := pipe.Pipe()
	c2.SetLocalAddr(s.Addr())
	c2.SetRemoteAddr(&addr{addr: r.RemoteAddr, id: s.id.Generate()})

	select {
	case <-r.Context().Done():
		_ = c1.Close()
		_ = c2.Close()
		return
	case <-s.closedCtx.Done():
		_ = c1.Close()
		_ = c2.Close()
		return
	case s.connChan <- c2:
	}

	go func() {
		_, err := relay.Copy(c1, r.Body)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "stream error:") {
			log.Error("http2.v2 relay request failed", "err", err)
		}
		_ = c1.Close()
	}()

	_, err := relay.Copy(&flusher{w: w}, c1)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
		log.Error("http2.v2 flush response failed", "err", err)
	}
}

type flusher struct {
	w http.ResponseWriter
}

func (f *flusher) Write(b []byte) (int, error) {
	n, err := f.w.Write(b)
	if flush, ok := f.w.(http.Flusher); ok {
		flush.Flush()
	}
	return n, err
}

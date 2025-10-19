package websocket

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/http"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	websocket "github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket/x"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type Server struct {
	net.Listener
	server   *http.Server
	connChan chan net.Conn
	closeCtx context.Context
	close    context.CancelFunc
}

func init() {
	register.RegisterTransport(NewServer)
}

func NewServer(c *config.Websocket, ii netapi.Listener) (netapi.Listener, error) {
	return netapi.NewListener(newServer(ii), ii), nil
}

func newServer(lis net.Listener) *Server {
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
		log.IfErr("websocket serve", func() error { return s.server.Serve(lis) })
	}()

	return s
}

func (s *Server) Close() error {
	var err error
	s.close()
	err = s.server.Close()
	if er := s.Listener.Close(); er != nil {
		err = errors.Join(err, er)
	}

	return err
}

func (s *Server) Accept() (net.Conn, error) {
	select {
	case conn := <-s.connChan:
		return conn, nil
	case <-s.closeCtx.Done():
		return nil, net.ErrClosed
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var earlyData []byte
	wsconn, err := websocket.NewServerConn(w, req, func(r *websocket.Request) error {
		if r.Request.Header.Get("early_data") == "base64" {

			earlyData = pool.GetBytes(base64.RawStdEncoding.DecodedLen(len(r.SecWebSocketKey)))
			n, err := base64.RawStdEncoding.Decode(earlyData, []byte(r.SecWebSocketKey))
			if err != nil {
				pool.PutBytes(earlyData)
				return err
			}

			earlyData = earlyData[:n]

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
	case s.connChan <- pool.NewBytesConn(wsconn, earlyData):
	}
}

package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/quic-go/quic-go"
)

type Server struct {
	packetConn net.PacketConn
	*quic.Listener
	tlsConfig *tls.Config

	ctx      context.Context
	cancel   context.CancelFunc
	connChan chan *interConn

	handler netapi.Handler
}

func NewServer(packetConn net.PacketConn, tlsConfig *tls.Config, handler netapi.Handler) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		packetConn: packetConn,
		tlsConfig:  tlsConfig,
		ctx:        ctx,
		cancel:     cancel,
		connChan:   make(chan *interConn, 10),
		handler:    handler,
	}

	var err error
	s.Listener, err = quic.Listen(s.packetConn, s.tlsConfig, &quic.Config{
		MaxIncomingStreams: 2048,
		KeepAlivePeriod:    0,
		MaxIdleTimeout:     60 * time.Second,
		EnableDatagrams:    true,
		Allow0RTT:          true,
	})
	if err != nil {
		return nil, err
	}

	go func() {
		defer s.Close()
		if err := s.server(); err != nil {
			log.Error("quic server failed:", "err", err)
		}
	}()

	return s, nil
}

func (s *Server) Close() error {
	var err error

	s.cancel()
	if s.packetConn != nil {
		if er := s.packetConn.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	return err
}

func (s *Server) Accept() (net.Conn, error) {
	select {
	case conn := <-s.connChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func (s *Server) server() error {
	for {
		conn, err := s.Listener.Accept(s.ctx)
		if err != nil {
			return err
		}

		go s.listenQuicConnection(conn)
	}
}

func (s *Server) listenQuicConnection(conn quic.Connection) {
	defer conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "") // nolint:errcheck
	// because of https://github.com/quic-go/quic-go/blob/5b72f4c900f209b5705bb0959399d59e495a2c6e/internal/protocol/params.go#L137
	// MaxDatagramFrameSize Too short, here use stream trans udp data until quic-go will auto frag lager frame
	// udp
	go func() {
		conn := NewConnectionPacketConn(context.Background(), conn)
		for {
			id, data, addr, err := conn.Receive()
			if err != nil {
				log.Error("receive message failed:", "err", err)
				break
			}

			address, err := netapi.ParseSysAddr(addr)
			if err != nil {
				log.Error("parse address failed:", "err", err)
				continue
			}

			s.handler.Packet(conn.conn.Context(), &netapi.Packet{
				Src:     &QuicAddr{Addr: conn.conn.RemoteAddr(), ID: quic.StreamID(id)},
				Dst:     address,
				Payload: pool.NewBytesV2(data),
				WriteBack: func(b []byte, addr net.Addr) (int, error) {
					err := conn.Write(b, id, addr)
					if err != nil {
						return 0, err
					}

					return len(b), nil
				},
			})
		}
	}()

	for {
		stream, err := conn.AcceptStream(s.ctx)
		if err != nil {
			break
		}

		select {
		case <-s.ctx.Done():
			return
		case s.connChan <- &interConn{Stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr()}:
			log.Info("new quic conn from", conn.RemoteAddr(), "id", stream.StreamID())
		}
	}
}

type QuicAddr struct {
	Addr net.Addr
	ID   quic.StreamID
}

func (q *QuicAddr) String() string  { return fmt.Sprint(q.Addr, q.ID) }
func (q *QuicAddr) Network() string { return "quic" }

package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/quic-go/quic-go"
)

type Server struct {
	packetConn net.PacketConn
	*quic.Listener

	ctx      context.Context
	cancel   context.CancelFunc
	connChan chan *interConn

	packetChan chan serverMsg
	natMap     syncmap.SyncMap[string, *ConnectionPacketConn]
}

func init() {
	listener.RegisterNetwork(NewServer)
}

func NewServer(c *listener.Inbound_Quic) (netapi.Listener, error) {
	packetConn, err := dialer.ListenPacket("udp", c.Quic.Host)
	if err != nil {
		return nil, err
	}

	tlsConfig, err := listener.ParseTLS(c.Quic.Tls)
	if err != nil {
		return nil, err
	}

	return newServer(packetConn, tlsConfig)
}

func newServer(packetConn net.PacketConn, tlsConfig *tls.Config) (*Server, error) {
	tr := quic.Transport{
		Conn:               packetConn,
		ConnectionIDLength: 12,
	}
	lis, err := tr.Listen(tlsConfig, &quic.Config{
		MaxIncomingStreams: 2048,
		KeepAlivePeriod:    45 * time.Second,
		MaxIdleTimeout:     60 * time.Second,
		EnableDatagrams:    true,
		Allow0RTT:          true,
	})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		packetConn: packetConn,
		ctx:        ctx,
		cancel:     cancel,
		connChan:   make(chan *interConn, 100),
		packetChan: make(chan serverMsg, 100),
		Listener:   lis,
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

func (s *Server) Packet(context.Context) (net.PacketConn, error) {
	ctx, cancel := context.WithCancel(s.ctx)
	return &serverPacketConn{Server: s, ctx: ctx, cancel: cancel}, nil
}

func (s *Server) Stream(ctx context.Context) (net.Listener, error) {
	return s, nil
}

func (s *Server) server() error {
	for {
		conn, err := s.Listener.Accept(s.ctx)
		if err != nil {
			return err
		}

		go func() {
			if err := s.listenQuicConnection(conn); err != nil {
				log.Error("listen quic connection failed:", "err", err)
			}
		}()
	}
}

func (s *Server) listenQuicConnection(conn quic.Connection) error {
	defer conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "") // nolint:errcheck

	raddr := conn.RemoteAddr()

	packetConn := NewConnectionPacketConn(conn)

	s.natMap.Store(raddr.String(), packetConn)
	defer s.natMap.Delete(raddr.String())

	// because of https://github.com/quic-go/quic-go/blob/5b72f4c900f209b5705bb0959399d59e495a2c6e/internal/protocol/params.go#L137
	// MaxDatagramFrameSize Too short, here use stream trans udp data until quic-go will auto frag lager frame
	// udp
	go func() {
		for {
			id, data, err := packetConn.Receive(s.ctx)
			if err != nil {
				log.Error("receive message failed:", "err", err)
				return
			}

			select {
			case <-s.ctx.Done():
				return
			case s.packetChan <- serverMsg{msg: data, src: raddr, id: id}:
			}
		}
	}()

	for {
		stream, err := conn.AcceptStream(s.ctx)
		if err != nil {
			return err
		}

		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case s.connChan <- &interConn{
			Stream:  stream,
			session: conn,
		}:
		}
	}
}

type serverMsg struct {
	msg []byte
	src net.Addr
	id  uint64
}
type serverPacketConn struct {
	*Server

	ctx    context.Context
	cancel context.CancelFunc

	deadline *time.Timer
}

func (x *serverPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case <-x.Server.ctx.Done():
		return 0, nil, x.ctx.Err()
	case <-x.ctx.Done():
		return 0, nil, io.EOF
	case msg := <-x.packetChan:
		n = copy(p, msg.msg)
		return n, &QuicAddr{Addr: msg.src, ID: quic.StreamID(msg.id)}, nil
	}
}

func (x *serverPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	select {
	case <-x.Server.ctx.Done():
		return 0, x.ctx.Err()
	case <-x.ctx.Done():
		return 0, io.EOF
	default:
	}

	qaddr, ok := addr.(*QuicAddr)
	if !ok {
		return 0, errors.New("invalid addr")
	}

	conn, ok := x.natMap.Load(qaddr.Addr.String())
	if !ok {
		return 0, fmt.Errorf("no such addr: %s", addr.String())
	}
	err = conn.Write(p, uint64(qaddr.ID))
	return len(p), err
}

func (x *serverPacketConn) LocalAddr() net.Addr {
	return x.Addr()
}

func (x *serverPacketConn) SetDeadline(t time.Time) error {
	if x.deadline == nil {
		if !t.IsZero() {
			x.deadline = time.AfterFunc(time.Until(t), func() { x.cancel() })
		}
		return nil
	}

	if t.IsZero() {
		x.deadline.Stop()
	} else {
		x.deadline.Reset(time.Until(t))
	}
	return nil
}

func (x *serverPacketConn) SetReadDeadline(t time.Time) error  { return x.SetDeadline(t) }
func (x *serverPacketConn) SetWriteDeadline(t time.Time) error { return x.SetDeadline(t) }

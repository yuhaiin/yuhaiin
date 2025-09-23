package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
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
	register.RegisterNetwork(NewServer)
}

func NewServer(c *listener.Quic) (netapi.Listener, error) {
	packetConn, err := dialer.ListenPacket(context.TODO(), "udp", c.GetHost(), dialer.WithListener())
	if err != nil {
		return nil, err
	}

	tlsConfig, err := register.ParseTLS(c.GetTls())
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

	config := &quic.Config{
		MaxIncomingStreams:    1 << 60,
		KeepAlivePeriod:       0,
		MaxIdleTimeout:        3 * time.Minute,
		EnableDatagrams:       true,
		Allow0RTT:             true,
		MaxIncomingUniStreams: -1,
	}

	lis, err := tr.Listen(tlsConfig, config)
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
		if err := s.server(); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("quic server failed:", "err", err)
		}
	}()

	return s, nil
}

func (s *Server) Close() error {
	var err error

	s.cancel()
	if s.Listener != nil {
		if er := s.Listener.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}
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

func (s *Server) Packet(context.Context) (net.PacketConn, error)   { return newServerPacketConn(s), nil }
func (s *Server) Stream(ctx context.Context) (net.Listener, error) { return s, nil }

func (s *Server) server() error {
	for {
		conn, err := s.Listener.Accept(s.ctx)
		if err != nil {
			return err
		}

		go func() {
			defer conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "") // nolint:errcheck

			go func() {
				if err := s.listenDatagram(conn); err != nil && !errors.Is(err, context.Canceled) {
					log.Error("listen datagram failed:", "err", err)
				}
			}()

			if err := s.listenStream(conn); err != nil && !errors.Is(err, context.Canceled) {
				log.Error("listen quic connection failed:", "err", err)
			}
		}()
	}
}

func (s *Server) listenDatagram(conn *quic.Conn) error {
	raddr := conn.RemoteAddr()

	packetConn := NewConnectionPacketConn(conn)

	s.natMap.Store(raddr.String(), packetConn)
	defer s.natMap.Delete(raddr.String())

	for {
		id, data, err := packetConn.Receive(s.ctx)
		if err != nil {
			return err
		}

		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case s.packetChan <- serverMsg{msg: data, src: raddr, id: id}:
		}
	}
}
func (s *Server) listenStream(conn *quic.Conn) error {
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
	msg *pool.Buffer
	src net.Addr
	id  uint64
}
type serverPacketConn struct {
	*Server

	ctx    context.Context
	cancel context.CancelFunc

	readDeadline  pipe.PipeDeadline
	writeDeadline pipe.PipeDeadline
}

func newServerPacketConn(s *Server) *serverPacketConn {
	ctx, cancel := context.WithCancel(s.ctx)
	return &serverPacketConn{
		Server:        s,
		ctx:           ctx,
		cancel:        cancel,
		readDeadline:  pipe.MakePipeDeadline(),
		writeDeadline: pipe.MakePipeDeadline(),
	}
}

func (x *serverPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case <-x.Server.ctx.Done():
		x.cancel()
		return 0, nil, io.ErrClosedPipe
	case <-x.ctx.Done():
		return 0, nil, io.ErrClosedPipe
	case <-x.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	case msg := <-x.packetChan:
		defer msg.msg.Reset()

		n = copy(p, msg.msg.Bytes())
		return n, &QuicAddr{Addr: msg.src, ID: quic.StreamID(msg.id)}, nil
	}
}

func (x *serverPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	select {
	case <-x.Server.ctx.Done():
		return 0, io.ErrClosedPipe
	case <-x.ctx.Done():
		return 0, io.ErrClosedPipe
	case <-x.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
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
	select {
	case <-x.Server.ctx.Done():
		return x.Server.ctx.Err()
	case <-x.ctx.Done():
		return x.ctx.Err()
	default:
	}

	_ = x.SetWriteDeadline(t)
	_ = x.SetReadDeadline(t)
	return nil
}

func (x *serverPacketConn) SetReadDeadline(t time.Time) error {
	x.readDeadline.Set(t)
	return nil
}

func (x *serverPacketConn) SetWriteDeadline(t time.Time) error {
	x.writeDeadline.Set(t)
	return nil
}

func (x *serverPacketConn) Close() error {
	x.cancel()
	return x.Server.Close()
}

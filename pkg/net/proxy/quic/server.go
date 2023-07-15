package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/quic-go/quic-go"
)

type Server struct {
	packetConn net.PacketConn
	*quic.Listener
	tlsConfig *tls.Config

	mu       sync.RWMutex
	connChan chan *interConn
	closed   bool
}

func NewServer(packetConn net.PacketConn, tlsConfig *tls.Config) (*Server, error) {
	s := &Server{
		packetConn: packetConn,
		tlsConfig:  tlsConfig,
		connChan:   make(chan *interConn, 10),
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}

	var err error

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

	close(s.connChan)
	s.closed = true

	return err
}

func (s *Server) Accept() (net.Conn, error) {
	conn, ok := <-s.connChan
	if !ok {
		return nil, net.ErrClosed
	}

	return conn, nil
}

func (s *Server) server() error {
	for {
		if s.closed {
			return net.ErrClosed
		}

		conn, err := s.Listener.Accept(context.TODO())
		if err != nil {
			return err
		}

		go s.listenQuicConnection(conn)
	}
}

func (s *Server) listenQuicConnection(conn quic.Connection) {
	defer conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")
	/*
		because of https://github.com/quic-go/quic-go/blob/5b72f4c900f209b5705bb0959399d59e495a2c6e/internal/protocol/params.go#L137
		MaxDatagramFrameSize Too short, here use stream trans udp data until quic-go will auto frag lager frame
			// udp
			go func() {
				for {
					data, err := conn.ReceiveMessage()
					if err != nil {
						log.Println("receive message failed:", err)
						break
					}

					if err = y.handleQuicDatagram(data, conn); err != nil {
						log.Println("handle datagram failed:", err)
					}
				}
			}()
	*/
	for {
		stream, err := conn.AcceptStream(context.TODO())
		if err != nil {
			break
		}

		s.mu.RLock()
		if s.closed {
			s.mu.RUnlock()
			break
		}

		log.Info("new quic conn from", conn.RemoteAddr(), "id", stream.StreamID())

		s.connChan <- &interConn{
			Stream: stream,
			local:  conn.LocalAddr(),
			remote: conn.RemoteAddr(),
		}

		s.mu.RUnlock()
	}

}

/*
	func (s *Server) handleQuicDatagram(b []byte, session quic.Connection) error {
		if len(b) <= 5 {
			return fmt.Errorf("invalid datagram")
		}

		id := binary.BigEndian.Uint16(b[:2])
		addr, err := s5c.ResolveAddr(bytes.NewBuffer(b[2:]))
		if err != nil {
			return err
		}

		log.Println("new udp from", session.RemoteAddr(), "id", id, "to", addr.Address(statistic.Type_udp))

		return c.nat.Write(&nat.Packet{
			SourceAddress: &QuicAddr{
				addr: session.RemoteAddr(),
				id:   quic.StreamID(id),
			},
			DestinationAddress: addr.Address(statistic.Type_udp),
			Payload:            b[2+len(addr):],
			WriteBack: func(b []byte, addr net.Addr) (int, error) {
				add, err := proxy.ParseSysAddr(addr)
				if err != nil {
					return 0, err
				}

				buf := pool.GetBuffer()
				defer pool.PutBuffer(buf)

				binary.Write(buf, binary.BigEndian, id)
				s5c.ParseAddrWriter(add, buf)
				buf.Write(b)

				// log.Println("write back to", session.RemoteAddr(), "id", id)
				if err = session.SendMessage(buf.Bytes()); err != nil {
					return 0, err
				}

				return len(b), nil
			},
		})
	}
*/
type QuicAddr struct {
	Addr net.Addr
	ID   quic.StreamID
}

func (q *QuicAddr) String() string  { return fmt.Sprint(q.Addr, q.ID) }
func (q *QuicAddr) Network() string { return "quic" }

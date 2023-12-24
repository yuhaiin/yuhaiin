package simple

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

type Server struct {
	net.Listener
	net.PacketConn

	host string
	mu   sync.Mutex
}

func (s *Server) Close() error {
	var err error

	if s.Listener != nil {
		if er := s.Listener.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	if s.PacketConn != nil {
		if er := s.PacketConn.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	return err
}

func (s *Server) initPacketConn() error {
	if s.PacketConn != nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.PacketConn != nil {
		return nil
	}

	p, err := dialer.ListenPacket("udp", s.host)
	if err != nil {
		return err
	}

	s.PacketConn = p

	return nil
}

func (s *Server) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if err := s.initPacketConn(); err != nil {
		return 0, nil, err
	}

	return s.PacketConn.ReadFrom(p)
}
func (s *Server) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if err := s.initPacketConn(); err != nil {
		return 0, err
	}

	return s.PacketConn.WriteTo(p, addr)
}

func NewServer(c *listener.Inbound_Tcpudp) (listener.InboundI, error) {
	lis, err := dialer.ListenContext(context.TODO(), "tcp", c.Tcpudp.Host)
	if err != nil {
		return nil, err
	}

	return &Server{
		Listener: lis,
		host:     c.Tcpudp.Host,
	}, nil
}

func init() {
	listener.RegisterNetwork(NewServer)
}

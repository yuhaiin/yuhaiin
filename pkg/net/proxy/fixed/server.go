package fixed

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

type Server struct {
	net.Listener
	net.PacketConn

	host string
	pmu  sync.Mutex
	smu  sync.Mutex

	control config.TcpUdpControl
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

	s.pmu.Lock()
	defer s.pmu.Unlock()

	if s.PacketConn != nil {
		return nil
	}

	p, err := dialer.ListenPacket(context.TODO(), "udp", s.host, dialer.WithListener())
	if err != nil {
		return err
	}

	s.PacketConn = p

	return nil
}

func (s *Server) initStream() error {
	if s.Listener != nil {
		return nil
	}

	s.smu.Lock()
	defer s.smu.Unlock()

	if s.Listener != nil {
		return nil
	}

	lis, err := dialer.ListenContext(context.TODO(), "tcp", s.host)
	if err != nil {
		return err
	}

	s.Listener = lis

	return nil
}

func (s *Server) Packet(ctx context.Context) (net.PacketConn, error) {
	if s.control == config.TcpUdpControl_disable_udp {
		return nil, errors.ErrUnsupported
	}

	if err := s.initPacketConn(); err != nil {
		return nil, err
	}

	return s.PacketConn, nil
}

func (s *Server) Accept() (net.Conn, error) {
	if s.control == config.TcpUdpControl_disable_tcp {
		return nil, errors.ErrUnsupported
	}

	if err := s.initStream(); err != nil {
		return nil, err
	}

	return s.Listener.Accept()
}

func (s *Server) Addr() net.Addr {
	if s.control == config.TcpUdpControl_disable_tcp {
		return netapi.EmptyAddr
	}

	if err := s.initStream(); err != nil {
		return netapi.EmptyAddr
	}

	return s.Listener.Addr()
}

func NewServer(c *config.Tcpudp) (netapi.Listener, error) {
	return &Server{
		host:    c.GetHost(),
		control: c.GetControl(),
	}, nil
}

func init() {
	register.RegisterNetwork(NewServer)
}

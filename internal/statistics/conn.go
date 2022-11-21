package statistics

import (
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

type connection interface {
	io.Closer
	Info() *statistic.Connection
}

var _ connection = (*conn)(nil)

type conn struct {
	net.Conn

	*statistic.Connection
	manager *Connections
}

func (s *conn) Close() error {
	s.manager.Remove(s.Id)
	return s.Conn.Close()
}

func (s *conn) Write(b []byte) (_ int, err error) {
	n, err := s.Conn.Write(b)
	s.manager.Upload.Add(uint64(n))
	return int(n), err
}

func (s *conn) Read(b []byte) (n int, err error) {
	n, err = s.Conn.Read(b)
	s.manager.Download.Add(uint64(n))
	return
}

func (s *conn) Info() *statistic.Connection { return s.Connection }

var _ connection = (*packetConn)(nil)

type packetConn struct {
	net.PacketConn

	*statistic.Connection
	manager *Connections
}

func (s *packetConn) Info() *statistic.Connection {
	return s.Connection
}

func (s *packetConn) Close() error {
	s.manager.Remove(s.Id)
	return s.PacketConn.Close()
}

func (s *packetConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = s.PacketConn.WriteTo(p, addr)
	s.manager.Upload.Add(uint64(n))
	return
}

func (s *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = s.PacketConn.ReadFrom(p)
	s.manager.Download.Add(uint64(n))
	return
}

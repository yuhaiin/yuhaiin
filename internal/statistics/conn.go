package statistics

import (
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

type connection interface {
	io.Closer

	GetType() *statistic.ConnectionNetType
	GetId() int64
	GetAddr() string
	GetLocal() string
	GetRemote() string
	GetExtra() map[string]string
	Info() *statistic.Connection
}

var _ connection = (*conn)(nil)

type conn struct {
	net.Conn

	*statistic.Connection
	manager *counter
}

func (s *conn) Close() error {
	s.manager.delete(s.Id)
	return s.Conn.Close()
}

func (s *conn) Write(b []byte) (_ int, err error) {
	n, err := s.Conn.Write(b)
	s.manager.AddUpload(uint64(n))
	return int(n), err
}

func (s *conn) Read(b []byte) (n int, err error) {
	n, err = s.Conn.Read(b)
	s.manager.AddDownload(uint64(n))
	return
}

func (s *conn) Info() *statistic.Connection { return s.Connection }

var _ connection = (*packetConn)(nil)

type packetConn struct {
	net.PacketConn

	*statistic.Connection
	manager *counter
}

func (s *packetConn) Info() *statistic.Connection {
	return s.Connection
}

func (s *packetConn) Close() error {
	s.manager.delete(s.Id)
	return s.PacketConn.Close()
}

func (s *packetConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = s.PacketConn.WriteTo(p, addr)
	s.manager.AddUpload(uint64(n))
	return
}

func (s *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = s.PacketConn.ReadFrom(p)
	s.manager.AddDownload(uint64(n))
	return
}

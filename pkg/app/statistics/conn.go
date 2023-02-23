package statistics

import (
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
)

type connection interface {
	io.Closer
	LocalAddr() net.Addr
	Addr() proxy.Address
	ID() uint64
}

var _ connection = (*conn)(nil)

type conn struct {
	net.Conn

	id      uint64
	addr    proxy.Address
	manager *Connections
}

func (s *conn) Close() error {
	s.manager.Remove(s.id)
	return s.Conn.Close()
}

func (s *conn) Write(b []byte) (_ int, err error) {
	n, err := s.Conn.Write(b)
	s.manager.Cache.AddUpload(uint64(n))
	return int(n), err
}

func (s *conn) Read(b []byte) (n int, err error) {
	n, err = s.Conn.Read(b)
	s.manager.Cache.AddDownload(uint64(n))
	return
}

func (s *conn) Addr() proxy.Address { return s.addr }
func (s *conn) ID() uint64          { return s.id }

var _ connection = (*packetConn)(nil)

type packetConn struct {
	net.PacketConn

	id      uint64
	addr    proxy.Address
	manager *Connections
}

func (s *packetConn) Addr() proxy.Address { return s.addr }
func (s *packetConn) ID() uint64          { return s.id }

func (s *packetConn) Close() error {
	s.manager.Remove(s.id)
	return s.PacketConn.Close()
}

func (s *packetConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = s.PacketConn.WriteTo(p, addr)
	s.manager.Cache.AddUpload(uint64(n))
	return
}

func (s *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = s.PacketConn.ReadFrom(p)
	s.manager.Cache.AddDownload(uint64(n))
	return
}

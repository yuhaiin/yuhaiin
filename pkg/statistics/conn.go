package statistics

import (
	"io"
	"net"
)

type connection interface {
	io.Closer
	ID() uint64
}

type counter interface {
	AddDownload(uint64)
	AddUpload(uint64)
}

var _ connection = (*conn)(nil)

type conn struct {
	net.Conn

	counter counter
	onClose func()

	id uint64
}

func (s *conn) Close() error {
	err := s.Conn.Close()
	if s.onClose != nil {
		s.onClose()
	}
	return err
}

func (s *conn) Write(b []byte) (_ int, err error) {
	n, err := s.Conn.Write(b)
	s.counter.AddUpload(uint64(n))
	return int(n), err
}

func (s *conn) Read(b []byte) (n int, err error) {
	n, err = s.Conn.Read(b)
	s.counter.AddDownload(uint64(n))
	return
}

func (s *conn) ID() uint64 { return s.id }

var _ connection = (*packetConn)(nil)

type packetConn struct {
	net.PacketConn

	counter counter
	onClose func()

	id uint64
}

func (s *packetConn) Close() error {
	err := s.PacketConn.Close()
	if s.onClose != nil {
		s.onClose()
	}
	return err
}

func (s *packetConn) ID() uint64 { return s.id }

func (s *packetConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = s.PacketConn.WriteTo(p, addr)
	s.counter.AddUpload(uint64(n))
	return
}

func (s *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = s.PacketConn.ReadFrom(p)
	s.counter.AddDownload(uint64(n))
	return
}

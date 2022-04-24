package statistic

import (
	"errors"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

type connection interface {
	io.Closer

	GetType() string
	GetId() int64
	GetAddr() string
	GetLocal() string
	GetRemote() string
	GetMark() string
	GetStatistic() *statistic.Connection
}

var _ connection = (*conn)(nil)

type conn struct {
	net.Conn

	*statistic.Connection
	manager *Statistic
}

func (s *conn) Close() error {
	s.manager.delete(s.Id)
	return s.Conn.Close()
}

func (s *conn) Write(b []byte) (n int, err error) {
	n, err = s.Conn.Write(b)
	s.manager.accountant.AddUpload(uint64(n))
	return
}

func (s *conn) Read(b []byte) (n int, err error) {
	n, err = s.Conn.Read(b)
	s.manager.accountant.AddDownload(uint64(n))
	return
}

func (s *conn) ReadFrom(r io.Reader) (resp int64, err error) {
	buf := utils.GetBytes(2048)
	defer utils.PutBytes(buf)

	for {
		n, er := r.Read(buf)
		if n > 0 {
			resp += int64(n)
			_, ew := s.Write(buf[:n])
			if ew != nil {
				break
			}
		}
		if er != nil {
			if !errors.Is(er, io.EOF) {
				err = er
			}
			break
		}
	}

	return
}

func (s *conn) WriteTo(w io.Writer) (resp int64, err error) {
	buf := utils.GetBytes(2048)
	defer utils.PutBytes(buf)

	for {
		n, er := s.Read(buf)
		if n > 0 {
			resp += int64(n)
			_, ew := w.Write(buf[:n])
			if ew != nil {
				break
			}
		}
		if er != nil {
			if !errors.Is(er, io.EOF) {
				err = er
			}
			break
		}
	}

	return
}

func (s *conn) GetStatistic() *statistic.Connection {
	return s.Connection
}

var _ connection = (*packetConn)(nil)

type packetConn struct {
	net.PacketConn

	*statistic.Connection
	manager *Statistic
}

func (s *packetConn) GetStatistic() *statistic.Connection {
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

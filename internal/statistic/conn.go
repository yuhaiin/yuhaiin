package statistic

import (
	"bytes"
	"errors"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
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
	Info() *statistic.Connection
}

var _ connection = (*conn)(nil)

type conn struct {
	net.Conn

	*statistic.Connection
	manager *counter

	wbuf, rbuf []byte
}

func (c *counter) AddConn(con net.Conn, addr proxy.Address, mark string) net.Conn {
	z := &conn{
		Connection: &statistic.Connection{
			Id:     c.idSeed.Generate(),
			Addr:   addr.String(),
			Mark:   mark,
			Local:  con.LocalAddr().String(),
			Remote: con.RemoteAddr().String(),
			Type:   con.LocalAddr().Network(),
		},
		Conn:    con,
		manager: c,
	}

	c.storeConnection(z)
	return z
}

func (s *conn) Close() error {
	if s.wbuf != nil {
		utils.PutBytes(s.wbuf)
	}
	if s.rbuf != nil {
		utils.PutBytes(s.rbuf)
	}
	s.manager.delete(s.Id)
	return s.Conn.Close()
}

func (s *conn) Write(b []byte) (_ int, err error) {
	n, err := s.ReadFrom(bytes.NewBuffer(b))
	return int(n), err
}

func (s *conn) Read(b []byte) (n int, err error) {
	n, err = s.Conn.Read(b)
	s.manager.accountant.AddDownload(uint64(n))
	return
}

func (s *conn) ReadFrom(r io.Reader) (resp int64, err error) {
	if s.wbuf == nil {
		s.wbuf = utils.GetBytes(2048)
	}

	for {
		n, er := r.Read(s.wbuf)
		if n > 0 {
			resp += int64(n)
			s.manager.accountant.AddUpload(uint64(n))
			_, ew := s.Conn.Write(s.wbuf[:n])
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
	if s.rbuf == nil {
		s.rbuf = utils.GetBytes(2048)
	}
	for {
		n, er := s.Read(s.rbuf)
		if n > 0 {
			resp += int64(n)
			_, ew := w.Write(s.rbuf[:n])
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

func (s *conn) Info() *statistic.Connection {
	return s.Connection
}

var _ connection = (*packetConn)(nil)

type packetConn struct {
	net.PacketConn

	*statistic.Connection
	manager *counter
}

func (c *counter) AddPacketConn(con net.PacketConn, addr proxy.Address, mark string) net.PacketConn {
	z := &packetConn{
		Connection: &statistic.Connection{
			Id:     c.idSeed.Generate(),
			Addr:   addr.String(),
			Mark:   mark,
			Local:  con.LocalAddr().String(),
			Remote: addr.String(),
			Type:   con.LocalAddr().Network(),
		},
		PacketConn: con,
		manager:    c,
	}

	c.storeConnection(z)
	return z
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

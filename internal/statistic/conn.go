package statistic

import (
	"bytes"
	"errors"
	"fmt"
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
	GetExtra() map[string]string
	Info() *statistic.Connection
}

var _ connection = (*conn)(nil)

type conn struct {
	net.Conn

	*statistic.Connection
	manager *counter

	wbuf, rbuf [utils.DefaultSize / 4]byte
}

func (c *counter) AddConn(con net.Conn, addr proxy.Address) net.Conn {
	z := &conn{
		Connection: &statistic.Connection{
			Id:     c.idSeed.Generate(),
			Addr:   addr.String(),
			Local:  con.LocalAddr().String(),
			Remote: con.RemoteAddr().String(),
			Type:   fmt.Sprintf("TCP(%s)", con.LocalAddr().Network()),
			Extra:  extraMap(addr),
		},
		Conn:    con,
		manager: c,
	}

	c.storeConnection(z)
	return z
}

func (s *conn) Close() error {
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
	for {
		n, er := r.Read(s.wbuf[:])
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
	for {
		n, er := s.Read(s.rbuf[:])
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

func (s *conn) Info() *statistic.Connection { return s.Connection }

var _ connection = (*packetConn)(nil)

type packetConn struct {
	net.PacketConn

	*statistic.Connection
	manager *counter
}

func getStringValue(key any, addr proxy.Address) string {
	m, _ := addr.GetMark(key)
	r, ok := m.(string)
	if !ok {
		return ""
	}

	return r
}

func extraMap(addr proxy.Address) map[string]string {
	r := make(map[string]string)
	addr.RangeMark(func(k, v any) bool {
		kk, ok := k.(string)
		if !ok {
			return true
		}

		vv, ok := v.(string)
		if !ok {
			return true
		}

		r[kk] = vv
		return true
	})

	return r
}

func (c *counter) AddPacketConn(con net.PacketConn, addr proxy.Address) net.PacketConn {
	z := &packetConn{
		Connection: &statistic.Connection{
			Id:     c.idSeed.Generate(),
			Addr:   addr.String(),
			Local:  con.LocalAddr().String(),
			Remote: addr.String(),
			Type:   fmt.Sprintf("UDP(%s)", con.LocalAddr().Network()),
			Extra:  extraMap(addr),
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

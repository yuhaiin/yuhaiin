package statistic

import (
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

type statisticConn interface {
	io.Closer

	Type() string
	GetId() int64
	GetAddr() string
	GetLocal() string
	GetRemote() string
	GetMark() string
	GetConnResp() *statistic.ConnRespConnection
}

var _ statisticConn = (*conn)(nil)

type conn struct {
	*preConn
}

func (s *conn) Type() string {
	return "TCP"
}

func (s *conn) GetConnResp() *statistic.ConnRespConnection {
	return s.ConnRespConnection
}

func (s *conn) ReadFrom(r io.Reader) (resp int64, _ error) {
	buf := utils.GetBytes(2048)
	defer utils.PutBytes(buf)
	return io.CopyBuffer(s.preConn, r, buf)
}

func (s *conn) WriteTo(w io.Writer) (resp int64, _ error) {
	buf := utils.GetBytes(2048)
	defer utils.PutBytes(buf)
	return io.CopyBuffer(w, s.preConn, buf)
}

var _ net.Conn = (*preConn)(nil)

type preConn struct {
	net.Conn
	cm *Statistic
	*statistic.ConnRespConnection
}

func (s *preConn) Close() error {
	s.cm.delete(s.Id)
	return s.Conn.Close()
}

func (s *preConn) Write(b []byte) (n int, err error) {
	n, err = s.Conn.Write(b)
	s.cm.accountant.AddUpload(uint64(n))
	return
}

func (s *preConn) Read(b []byte) (n int, err error) {
	n, err = s.Conn.Read(b)
	s.cm.accountant.AddDownload(uint64(n))
	return
}

var _ net.PacketConn = (*packetConn)(nil)
var _ statisticConn = (*packetConn)(nil)

type packetConn struct {
	net.PacketConn
	cm *Statistic

	*statistic.ConnRespConnection
}

func (s *packetConn) Type() string {
	return "UDP"
}

func (s *packetConn) GetConnResp() *statistic.ConnRespConnection {
	return s.ConnRespConnection
}

func (s *packetConn) Close() error {
	s.cm.delete(s.Id)
	return s.PacketConn.Close()
}

func (s *packetConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = s.PacketConn.WriteTo(p, addr)
	s.cm.accountant.AddUpload(uint64(n))
	return
}

func (s *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = s.PacketConn.ReadFrom(p)
	s.cm.accountant.AddDownload(uint64(n))
	return
}

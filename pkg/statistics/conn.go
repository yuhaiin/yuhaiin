package statistics

import (
	"io"
	"log/slog"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

type connection interface {
	io.Closer
	LocalAddr() net.Addr
	Info() *statistic.Connection
}

var _ connection = (*conn)(nil)

type conn struct {
	net.Conn

	info    *statistic.Connection
	manager *Connections
}

func (s *conn) Close() error {
	s.manager.Remove(s.info.GetId())
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

func (s *conn) Info() *statistic.Connection { return s.info }

var _ connection = (*packetConn)(nil)

type packetConn struct {
	net.PacketConn

	info    *statistic.Connection
	manager *Connections
}

func (s *packetConn) Info() *statistic.Connection { return s.info }

func (s *packetConn) Close() error {
	s.manager.Remove(s.info.GetId())
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

func connToStatistic(c connection) *statistic.Connection { return c.Info() }

func slogArgs(c connection) func() []any {
	return func() []any {
		info := c.Info()
		attrs := []any{
			slog.Any("id", info.GetId()),
			slog.Any("addr", info.Addr),
			slog.Any("src", info.Extra["Source"]),
			slog.Any("network", info.Type.ConnType),
			slog.Any("outbound", info.Extra["Outbound"]),
		}

		if info.Extra["Process"] != "" {
			attrs = append(attrs, slog.Any("process", info.Extra["Process"]))
		}

		if info.Extra["FakeIP"] != "" {
			attrs = append(attrs, slog.Any("fakeip", info.Extra["FakeIP"]))
		}

		if info.Extra["Hosts"] != "" {
			attrs = append(attrs, slog.Any("hosts", info.Extra["Hosts"]))
		}

		return attrs
	}
}

package statistics

import (
	"io"
	"log/slog"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
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

	id      uint64
	onClose func()
	counter counter
}

func (s *conn) Close() error {
	if s.onClose != nil {
		s.onClose()
	}
	return s.Conn.Close()
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

	id      uint64
	onClose func()

	counter counter
}

func (s *packetConn) Close() error {
	if s.onClose != nil {
		s.onClose()
	}
	return s.PacketConn.Close()
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

func slogArgs(info *statistic.Connection) func() []any {
	return func() []any {
		attrs := []any{
			slog.Any("id", info.GetId()),
			slog.Any("addr", info.GetAddr()),
			slog.Any("src", info.GetSource()),
			slog.Any("network", info.GetType().GetConnType()),
			slog.Any("outbound", info.GetOutbound()),
		}

		if info.HasProcess() {
			attrs = append(attrs, slog.Any("process", info.GetProcess()))
		}

		if info.HasFakeIp() {
			attrs = append(attrs, slog.Any("fakeip", info.GetFakeIp()))
		}

		if info.HasHosts() {
			attrs = append(attrs, slog.Any("hosts", info.GetHosts()))
		}

		return attrs
	}
}

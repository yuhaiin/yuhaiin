package statistics

import (
	"io"
	"log/slog"
	"net"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

type connection interface {
	io.Closer
	LoadDownload() uint64
	LoadUpload() uint64
	LocalAddr() net.Addr
	Info() *statistic.Connection
}

var _ connection = (*conn)(nil)

type conn struct {
	net.Conn

	counter

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
	s.counter.AddUpload(uint64(n))
	return int(n), err
}

func (s *conn) Read(b []byte) (n int, err error) {
	n, err = s.Conn.Read(b)
	s.manager.Cache.AddDownload(uint64(n))
	s.counter.AddDownload(uint64(n))
	return
}

func (s *conn) Info() *statistic.Connection { return s.info }

var _ connection = (*packetConn)(nil)

type packetConn struct {
	net.PacketConn

	counter

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
	s.counter.AddUpload(uint64(n))
	return
}

func (s *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = s.PacketConn.ReadFrom(p)
	s.manager.Cache.AddDownload(uint64(n))
	s.counter.AddDownload(uint64(n))
	return
}

func connToStatistic(c connection) *statistic.Connection { return c.Info() }

func slogArgs(c connection) func() []any {
	return func() []any {
		info := c.Info()

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

type counter struct {
	upload   atomic.Uint64
	download atomic.Uint64
}

func (c *counter) AddUpload(n uint64)   { c.upload.Add(n) }
func (c *counter) AddDownload(n uint64) { c.download.Add(n) }

func (c *counter) LoadUpload() uint64   { return c.upload.Load() }
func (c *counter) LoadDownload() uint64 { return c.download.Load() }

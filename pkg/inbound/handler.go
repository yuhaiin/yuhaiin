package inbound

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/sniff"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

type handler struct {
	dialer     netapi.Proxy
	dnsHandler netapi.DNSServer
	table      *nat.Table

	sniffer *controlSniffer
}

func NewHandler(dialer netapi.Proxy, dnsHandler netapi.DNSServer) *handler {
	sniffer := newControlSniffer()
	h := &handler{
		dialer:     dialer,
		table:      nat.NewTable(sniffer, dialer),
		dnsHandler: dnsHandler,
		sniffer:    sniffer,
	}

	return h
}

func (s *handler) logLevel(err error) slog.Level {
	level := netapi.LogLevel(err)
	if level == slog.LevelDebug {
		return slog.LevelDebug
	}

	if configuration.IgnoreDnsErrorLog.Load() {
		var derr *net.DNSError
		if errors.As(err, &derr) {
			return slog.LevelDebug
		}
	}

	if configuration.IgnoreTimeoutErrorLog.Load() {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return slog.LevelDebug
		}

		var netOpErr *net.OpError
		if errors.As(err, &netOpErr) && netOpErr.Timeout() {
			return slog.LevelDebug
		}

		var syscallErr syscall.Errno
		if errors.As(err, &syscallErr) {
			switch syscallErr {
			case syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH:
				return slog.LevelDebug
			}
		}
	}

	return slog.LevelError
}

func (s *handler) Stream(ctx *netapi.Context, meta *netapi.StreamMeta) {
	if err := s.stream(ctx, meta); err != nil {
		log.Select(s.logLevel(err)).Print("inbound handler stream", "msg", err)
	}
}

func (s *handler) stream(store *netapi.Context, meta *netapi.StreamMeta) error {
	ctx, cancel := context.WithTimeout(store, configuration.Timeout)
	defer cancel()

	dst := meta.Address

	startNanoSeconds := system.CheapNowNano()

	meta.Src = s.sniffer.Stream(store, meta.Src)
	defer meta.Src.Close()

	remote, err := s.dialer.Conn(ctx, dst)
	if err != nil {
		ne := netapi.NewDialError("tcp", err, dst)
		sniff := store.SniffHost()
		if sniff != "" {
			ne.Sniff = sniff
		}
		return ne
	}
	defer remote.Close()

	endNanoSeconds := system.CheapNowNano()

	metrics.Counter.AddStreamConnectDuration(float64(time.Duration(endNanoSeconds - startNanoSeconds).Milliseconds()))

	relay.Relay(meta.Src, remote, slog.Any("dst", dst), slog.Any("src", store.Source), slog.Any("process", store.Process))
	return nil
}

func (s *handler) Packet(ctx context.Context, pack *netapi.Packet) {
	// ! because we use ringbuffer which can drop the packet if the buffer is full
	// ! so here we assume the network is not congesting
	//
	// after 1.5s, we assume the network is congesting, just drop the packet
	// xctx, cancel := context.WithTimeout(store, time.Millisecond*1500)
	// defer cancel()

	if err := s.table.Write(ctx, pack); err != nil {
		log.Error("packet", "error", err)
	}
}

func (s *handler) Close() error { return s.table.Close() }

type controlSniffer struct {
	enabled atomic.Bool
	sniffer *sniff.Sniffier[bypass.Mode]
}

func newControlSniffer() *controlSniffer {
	return &controlSniffer{
		sniffer: sniff.New(),
	}
}

func (u *controlSniffer) Packet(ctx *netapi.Context, b []byte) {
	if u.enabled.Load() {
		u.sniffer.Packet(ctx, b)
	}
}

func (u *controlSniffer) Stream(ctx *netapi.Context, cc net.Conn) net.Conn {
	if u.enabled.Load() {
		return u.sniffer.Stream(ctx, cc)
	}
	return cc
}

func (c *controlSniffer) SetEnabled(enabled bool) {
	c.enabled.Store(enabled)
}

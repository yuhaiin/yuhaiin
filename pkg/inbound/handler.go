package inbound

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	"github.com/Asutorufa/yuhaiin/pkg/net/sniff"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

type handler struct {
	dialer     netapi.Proxy
	dnsHandler netapi.DNSServer
	table      *nat.Table

	sniffer *sniff.Sniffier[bypass.Mode]

	sniffyEnabled bool
}

func NewHandler(dialer netapi.Proxy, dnsHandler netapi.DNSServer) *handler {
	h := &handler{
		dialer:        dialer,
		table:         nat.NewTable(dialer),
		dnsHandler:    dnsHandler,
		sniffer:       sniff.New(),
		sniffyEnabled: true,
	}

	return h
}

func (s *handler) Stream(ctx context.Context, meta *netapi.StreamMeta) {
	go func() {
		if err := s.stream(ctx, meta); err != nil {
			log.Select(netapi.LogLevel(err)).Print("inbound handler stream", "msg", err)
		}
	}()
}

func (s *handler) stream(ctx context.Context, meta *netapi.StreamMeta) error {
	ctx, cancel := context.WithTimeout(ctx, configuration.Timeout)
	defer cancel()

	ctx = netapi.WithContext(ctx)
	defer meta.Src.Close()

	dst := meta.Address
	store := netapi.GetContext(ctx)

	store.Source = meta.Source
	store.Destination = meta.Destination
	if meta.Inbound != nil {
		store.Inbound = meta.Inbound
	}

	startNanoSeconds := system.CheapNowNano()

	if s.sniffyEnabled {
		src := s.sniffer.Stream(store, meta.Src)
		defer src.Close()
		meta.Src = src
	}

	remote, err := s.dialer.Conn(ctx, dst)
	if err != nil {
		sniff := store.SniffHost()
		if sniff != "" {
			sniff = fmt.Sprintf(" [sniff: %s]", sniff)
		}
		return fmt.Errorf("dial %s%s failed: %w", dst, sniff, err)
	}
	defer remote.Close()

	endNanoSeconds := system.CheapNowNano()

	metrics.Counter.AddStreamConnectDuration(time.Duration(endNanoSeconds - startNanoSeconds).Seconds())

	relay.Relay(meta.Src, remote, slog.Any("dst", dst), slog.Any("src", store.Source), slog.Any("process", store.Process))
	return nil
}

func (s *handler) Packet(xctx context.Context, pack *netapi.Packet) {
	xctx, cancel := context.WithTimeout(xctx, configuration.Timeout)
	defer cancel()

	ctx := netapi.WithContext(xctx)

	if s.sniffyEnabled {
		s.sniffer.Packet(ctx, pack.Payload)
	}

	_, ok := pack.Src.(*quic.QuicAddr)
	if !ok {
		src, err := netapi.ParseSysAddr(pack.Src)
		if err == nil && !src.IsFqdn() {
			srcAddr, _ := dialer.ResolverAddrPort(ctx, src)
			if srcAddr.Addr().Unmap().Is4() {
				ctx.Resolver.Mode = netapi.ResolverModePreferIPv4
			}
		}
	}

	if err := s.table.Write(ctx, pack); err != nil {
		log.Error("packet", "error", err)
	}
}

func (s *handler) Close() error { return s.table.Close() }

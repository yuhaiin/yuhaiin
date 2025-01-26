package inbound

import (
	"context"
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

func (s *handler) Stream(ctx *netapi.Context, meta *netapi.StreamMeta) {
	if err := s.stream(ctx, meta); err != nil {
		log.Select(netapi.LogLevel(err)).Print("inbound handler stream", "msg", err)
	}
}

func (s *handler) stream(store *netapi.Context, meta *netapi.StreamMeta) error {
	ctx, cancel := context.WithTimeout(store, configuration.Timeout)
	defer cancel()

	defer meta.Src.Close()

	dst := meta.Address

	startNanoSeconds := system.CheapNowNano()

	if s.sniffyEnabled {
		src := s.sniffer.Stream(store, meta.Src)
		defer src.Close()
		meta.Src = src
	}

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

	metrics.Counter.AddStreamConnectDuration(time.Duration(endNanoSeconds - startNanoSeconds).Seconds())

	relay.Relay(meta.Src, remote, slog.Any("dst", dst), slog.Any("src", store.Source), slog.Any("process", store.Process))
	return nil
}

func (s *handler) Packet(store *netapi.Context, pack *netapi.Packet) {
	if s.sniffyEnabled {
		s.sniffer.Packet(store, pack.Payload)
	}

	_, ok := pack.Src.(*quic.QuicAddr)
	if !ok {
		src, err := netapi.ParseSysAddr(pack.Src)
		if err == nil && !src.IsFqdn() {
			xctx, cancel := context.WithTimeout(store, time.Second*6)
			srcAddr, _ := dialer.ResolverAddrPort(xctx, src)
			cancel()
			if srcAddr.Addr().Unmap().Is4() {
				store.Resolver.Mode = netapi.ResolverModePreferIPv4
			}
		}
	}

	// ! because we use ringbuffer which can drop the packet if the buffer is full
	// ! so here we assume the network is not congesting
	//
	// after 1.5s, we assume the network is congesting, just drop the packet
	// xctx, cancel := context.WithTimeout(store, time.Millisecond*1500)
	// defer cancel()

	if err := s.table.Write(store, pack); err != nil {
		log.Error("packet", "error", err)
	}
}

func (s *handler) Close() error { return s.table.Close() }

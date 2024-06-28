package inbound

import (
	"context"
	"fmt"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	"github.com/Asutorufa/yuhaiin/pkg/net/sniffy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
)

var Timeout = time.Second * 20

type handler struct {
	dialer     netapi.Proxy
	dnsHandler netapi.DNSServer
	table      *nat.Table

	sniffer *sniffy.Sniffier[bypass.Mode]

	sniffyEnabled bool
}

func NewHandler(dialer netapi.Proxy, dnsHandler netapi.DNSServer) *handler {
	h := &handler{
		dialer:        dialer,
		table:         nat.NewTable(dialer),
		dnsHandler:    dnsHandler,
		sniffer:       sniffy.New(),
		sniffyEnabled: true,
	}

	return h
}

func (s *handler) Stream(ctx context.Context, meta *netapi.StreamMeta) {
	go func() {
		if err := s.stream(ctx, meta); err != nil {
			log.Output(0, netapi.LogLevel(err), "inbound handler stream", "msg", err)
		}
	}()
}

func (s *handler) stream(ctx context.Context, meta *netapi.StreamMeta) error {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
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

	if s.sniffyEnabled {
		src, mode, name, ok := s.sniffer.Stream(meta.Src)
		if ok {
			store.Protocol = name
			store.ForceMode = mode
		}
		defer src.Close()

		meta.Src = src
	}

	remote, err := s.dialer.Conn(ctx, dst)
	if err != nil {
		return fmt.Errorf("dial %s failed: %w", dst, err)
	}
	defer remote.Close()

	relay.Relay(meta.Src, remote)
	return nil
}

func (s *handler) Packet(xctx context.Context, pack *netapi.Packet) {
	xctx, cancel := context.WithTimeout(xctx, Timeout)
	defer cancel()

	ctx := netapi.WithContext(xctx)

	if s.sniffyEnabled {
		mode, name, ok := s.sniffer.Packet(pack.Payload)
		if ok {
			ctx.Protocol = name
			ctx.ForceMode = mode
		}
	}

	_, ok := pack.Src.(*quic.QuicAddr)
	if !ok {
		src, err := netapi.ParseSysAddr(pack.Src)
		if err == nil && !src.IsFqdn() {
			srcAddr, _ := netapi.ResolverAddrPort(ctx, src)
			if srcAddr.Addr().Unmap().Is4() {
				ctx.Resolver.PreferIPv4 = true
				ctx.Resolver.PreferIPv6 = false
			}
		}
	}

	if err := s.table.Write(ctx, pack); err != nil {
		log.Error("packet", "error", err)
	}
}

func (s *handler) Close() error { return s.table.Close() }

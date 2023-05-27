package inbound

import (
	"context"
	"fmt"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
)

var Timeout = time.Second * 20

type handler struct {
	dialer proxy.Proxy
	table  *nat.Table
}

func NewHandler(dialer proxy.Proxy) *handler {
	return &handler{
		dialer: dialer,
		table:  nat.NewTable(dialer),
	}
}

func (s *handler) Stream(ctx context.Context, meta *proxy.StreamMeta) {
	go func() {
		if err := s.stream(ctx, meta); err != nil {
			log.Error("stream", "error", err)
		}
	}()
}

func (s *handler) stream(ctx context.Context, meta *proxy.StreamMeta) error {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()

	ctx = proxy.NewStore(ctx)
	defer meta.Src.Close()

	dst := meta.Address
	store := proxy.StoreFromContext(ctx)

	store.Add(proxy.SourceKey{}, meta.Source).
		Add(proxy.DestinationKey{}, meta.Destination)
	if meta.Inbound != nil {
		store.Add(proxy.InboundKey{}, meta.Inbound)
	}

	remote, err := s.dialer.Conn(ctx, dst)
	if err != nil {
		return fmt.Errorf("dial %s failed: %w", dst, err)
	}
	defer remote.Close()

	relay.Relay(meta.Src, remote)
	return nil
}

func (s *handler) Packet(ctx context.Context, pack *proxy.Packet) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()

	ctx = proxy.NewStore(ctx)

	if err := s.table.Write(ctx, pack); err != nil {
		log.Error("packet", "error", err)
	}
}

func (s *handler) Close() error { return s.table.Close() }
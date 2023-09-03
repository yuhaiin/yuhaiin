package inbound

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

var Timeout = time.Second * 20

type packetChan struct {
	ctx    context.Context
	packet *netapi.Packet
}

type handler struct {
	dialer     netapi.Proxy
	table      *nat.Table
	packetChan chan packetChan

	doneCtx   context.Context
	cancelCtx func()
}

func NewHandler(dialer netapi.Proxy) *handler {
	ctx, cancel := context.WithCancel(context.Background())
	h := &handler{
		dialer:     dialer,
		table:      nat.NewTable(dialer),
		packetChan: make(chan packetChan, system.Procs),
		doneCtx:    ctx,
		cancelCtx:  cancel,
	}

	go func() {
		for {
			select {
			case pack := <-h.packetChan:
				go h.packet(pack.ctx, pack.packet)
			case <-h.doneCtx.Done():
				close(h.packetChan)
				return
			}
		}
	}()

	return h
}

func (s *handler) Stream(ctx context.Context, meta *netapi.StreamMeta) {
	go func() {
		if err := s.stream(ctx, meta); err != nil {
			if errors.Is(err, netapi.ErrBlocked) {
				log.Debug("blocked", "msg", err)
			} else {
				log.Error("stream", "error", err)
			}
		}
	}()
}

func (s *handler) stream(ctx context.Context, meta *netapi.StreamMeta) error {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()

	ctx = netapi.NewStore(ctx)
	defer meta.Src.Close()

	dst := meta.Address
	store := netapi.StoreFromContext(ctx)

	store.Add(netapi.SourceKey{}, meta.Source).
		Add(netapi.DestinationKey{}, meta.Destination)
	if meta.Inbound != nil {
		store.Add(netapi.InboundKey{}, meta.Inbound)
	}

	remote, err := s.dialer.Conn(ctx, dst)
	if err != nil {
		return fmt.Errorf("dial %s failed: %w", dst, err)
	}
	defer remote.Close()

	relay.Relay(meta.Src, remote)
	return nil
}

func (s *handler) Packet(ctx context.Context, pack *netapi.Packet) {
	select {
	case <-s.doneCtx.Done():
	default:
		s.packetChan <- packetChan{ctx, pack}
	}
}

func (s *handler) packet(ctx context.Context, pack *netapi.Packet) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()

	ctx = netapi.NewStore(ctx)

	if err := s.table.Write(ctx, pack); err != nil {
		log.Error("packet", "error", err)
	}
}

func (s *handler) Close() error {
	s.cancelCtx()
	return s.table.Close()
}

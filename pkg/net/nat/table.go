package nat

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var (
	IdleTimeout    = (time.Minute * 3) / 2
	MaxSegmentSize = pool.MaxSegmentSize
)

type Table struct {
	dialer        netapi.Proxy
	sinffer       netapi.PacketSniffer
	sourceControl syncmap.SyncMap[uint64, *SourceControl]
	closed        atomic.Bool

	timer *time.Ticker
}

func NewTable(sniffer netapi.PacketSniffer, dialer netapi.Proxy) *Table {
	t := &Table{
		dialer:  dialer,
		sinffer: sniffer,
		timer:   time.NewTicker(IdleTimeout),
	}

	go func() {
		for range t.timer.C {
			for k, v := range t.sourceControl.Range {
				idleTime, ok := v.IsIdle()
				if !ok {
					continue
				}

				if time.Since(idleTime) > IdleTimeout && t.sourceControl.CompareAndDelete(k, v) {
					if err := v.Close(); err != nil {
						log.Error("close source control failed", "err", err)
					}
				}
			}
		}
	}()

	return t
}

func (u *Table) Write(ctx context.Context, pkt *netapi.Packet) error {
	metrics.Counter.AddSendUDPPacket()
	metrics.Counter.AddSendUDPPacketSize(len(pkt.GetPayload()))

	if u.closed.Load() {
		return fmt.Errorf("udp nat table: %w", net.ErrClosed)
	}

	key := pkt.MigrateID

	if key == 0 {
		srcAddr, err := netapi.ParseSysAddr(pkt.Src())
		if err != nil {
			return fmt.Errorf("parse src addr failed: %w", err)
		}

		key = srcAddr.Comparable()
	}

	r, _, _ := u.sourceControl.LoadOrCreate(key, func() (*SourceControl, error) {
		return NewSourceChan(u.sinffer, u.dialer), nil
	})

	return r.WritePacket(ctx, pkt)
}

func (u *Table) Close() error {
	u.closed.Store(true)
	u.timer.Stop()
	for v := range u.sourceControl.RangeValues {
		_ = v.Close()
	}
	return nil
}

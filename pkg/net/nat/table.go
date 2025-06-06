package nat

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var IdleTimeout = time.Minute * 3
var MaxSegmentSize = pool.MaxSegmentSize

func NewTable(sniffer netapi.PacketSniffer, dialer netapi.Proxy) *Table {
	return &Table{dialer: dialer, sinffer: sniffer}
}

type Table struct {
	dialer        netapi.Proxy
	sinffer       netapi.PacketSniffer
	sourceControl syncmap.SyncMap[uint64, *SourceControl]
	closed        atomic.Bool
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
		return NewSourceChan(u.sinffer, u.dialer, func(sc *SourceControl) {
			u.sourceControl.CompareAndDelete(key, sc)
		}), nil
	})

	return r.WritePacket(ctx, pkt)
}

func (u *Table) Close() error {
	u.closed.Store(true)
	for v := range u.sourceControl.RangeValues {
		_ = v.Close()
	}
	return nil
}

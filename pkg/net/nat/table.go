package nat

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var IdleTimeout = time.Minute * 5
var MaxSegmentSize = pool.MaxSegmentSize

func NewTable(dialer netapi.Proxy) *Table {
	return &Table{dialer: dialer}
}

type Table struct {
	dialer        netapi.Proxy
	sourceControl syncmap.SyncMap[string, *SourceControl]
	closed        atomic.Bool
}

func (u *Table) Write(ctx context.Context, pkt *netapi.Packet) error {

	metrics.Counter.AddSendUDPPacket()

	if u.closed.Load() {
		return fmt.Errorf("udp nat table: %w", net.ErrClosed)
	}

	var key string

	if pkt.MigrateID != 0 {
		key = strconv.FormatUint(pkt.MigrateID, 10)
	} else {
		key = pkt.Src.String()
	}

	r, _ := u.sourceControl.LoadOrCreate(key, func() *SourceControl {
		return &SourceControl{
			Dialer:   u.dialer,
			OnRemove: func() { u.sourceControl.Delete(key) },
		}
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

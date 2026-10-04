package nat

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var (
	MaxSegmentSize = pool.MaxSegmentSize
)

func udpIdleTimeout() time.Duration {
	return configuration.UDPIdleTimeout.Load()
}

type Table struct {
	dialer  netapi.Proxy
	sinffer netapi.PacketSniffer

	timer         *time.Ticker
	sourceControl syncmap.SyncMap[uint64, *SourceControl]
	closed        atomic.Bool
	mu            sync.RWMutex // Serializes queue admission with Close.
	stop          chan struct{}
	done          chan struct{}
	closeOnce     sync.Once
}

func NewTable(sniffer netapi.PacketSniffer, dialer netapi.Proxy) *Table {
	t := &Table{
		dialer:  dialer,
		sinffer: sniffer,
		timer:   time.NewTicker(udpIdleTimeout()),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}

	go func() {
		defer close(t.done)
		for {
			// Ticker.Stop does not close C. An explicit stop signal is needed
			// to release this worker when the table is replaced or closed.
			select {
			case <-t.stop:
				return
			case <-t.timer.C:
			}
			idleTimeout := udpIdleTimeout()
			for k, v := range t.sourceControl.Range {
				idleTime, ok := v.IsIdle()
				if !ok {
					continue
				}

				if time.Since(idleTime) > idleTimeout && t.sourceControl.CompareAndDelete(k, v) {
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

	u.mu.RLock()
	defer u.mu.RUnlock()
	if u.closed.Load() {
		return fmt.Errorf("udp nat table: %w", net.ErrClosed)
	}
	r, _, _ := u.sourceControl.LoadOrCreate(key, func() (*SourceControl, error) {
		return NewSourceChan(u.sinffer, u.dialer), nil
	})

	return r.WritePacket(ctx, pkt)
}

func (u *Table) Close() error {
	u.closeOnce.Do(func() {
		u.mu.Lock()
		u.closed.Store(true)
		close(u.stop)
		u.timer.Stop()
		var controls []*SourceControl
		for v := range u.sourceControl.RangeValues {
			controls = append(controls, v)
		}
		u.sourceControl.Clear()
		u.mu.Unlock()
		// No writer can publish another control after the snapshot above.
		// Wait outside mu because closing a control may interrupt network I/O.
		for _, v := range controls {
			v.close()
		}
		for _, v := range controls {
			_ = v.Close()
		}
		<-u.done
	})
	return nil
}

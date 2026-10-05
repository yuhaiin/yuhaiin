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

	cleanerWake   chan struct{}
	sourceControl syncmap.SyncMap[uint64, *SourceControl]
	closed        atomic.Bool
	mu            sync.RWMutex // Serializes queue admission with Close.
	stop          chan struct{}
	done          chan struct{}
	closeOnce     sync.Once
}

func NewTable(sniffer netapi.PacketSniffer, dialer netapi.Proxy) *Table {
	t := &Table{
		dialer:      dialer,
		sinffer:     sniffer,
		cleanerWake: make(chan struct{}, 1),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
	}

	go t.runCleaner(udpIdleTimeout)

	return t
}

// Suspend cleanup while the NAT table is empty. Only publishing a new source
// starts the timer; existing sources do not signal it on each packet.
func (t *Table) runCleaner(interval func() time.Duration) {
	defer close(t.done)
	var timer *time.Timer
	var timerC <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	arm := func() {
		if timer == nil {
			timer = time.NewTimer(interval())
		} else {
			timer.Reset(interval())
		}
		timerC = timer.C
	}
	for {
		select {
		case <-t.stop:
			return
		case <-t.cleanerWake:
			if timerC == nil {
				arm()
			}
		case <-timerC:
			timerC = nil
			idleTimeout := interval()
			for k, v := range t.sourceControl.Range {
				idleTime, ok := v.IsIdle()
				if ok && time.Since(idleTime) > idleTimeout && t.sourceControl.CompareAndDelete(k, v) {
					if err := v.Close(); err != nil {
						log.Error("close source control failed", "err", err)
					}
				}
			}
			for range t.sourceControl.RangeValues {
				arm()
				break
			}
		}
	}
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
	r, loaded, _ := u.sourceControl.LoadOrCreate(key, func() (*SourceControl, error) {
		return NewSourceChan(u.sinffer, u.dialer), nil
	})

	if !loaded {
		select {
		case u.cleanerWake <- struct{}{}:
		default:
		}
	}
	return r.WritePacket(ctx, pkt)
}

func (u *Table) Close() error {
	u.closeOnce.Do(func() {
		u.mu.Lock()
		u.closed.Store(true)
		close(u.stop)
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

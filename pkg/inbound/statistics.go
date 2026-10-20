package inbound

import (
	"context"
	"errors"
	"maps"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/log"
)

const ingressStatisticsFlushInterval = 5 * time.Second

// IngressStatisticsStore persists lifetime listener ingress counters separately
// from the inbound configuration, listener health and lifecycle events.
type IngressStatisticsStore interface {
	LoadIngressStatistics(context.Context) (map[string]contract.IngressTotals, error)
	SaveIngressStatistics(context.Context, map[string]contract.IngressTotals) error
}

func (c *ingressCounters) snapshot() contract.IngressTotals {
	return contract.IngressTotals{
		AcceptedStreams: c.streams.Load(),
		ReceivedPackets: c.packets.Load(),
		ReceivedPings:   c.pings.Load(),
	}
}

func (c *ingressCounters) restore(value contract.IngressTotals) {
	c.streams.Store(value.AcceptedStreams)
	c.packets.Store(value.ReceivedPackets)
	c.pings.Store(value.ReceivedPings)
}

// WithIngressStatisticsStore wires the existing SQLite inbound store to the
// runtime. Call RestoreStatistics before synchronizing saved listeners.
func WithIngressStatisticsStore(store IngressStatisticsStore) Option {
	return func(l *Inbound) { l.statisticsStore = store }
}

// RestoreStatistics runs before listeners are activated, so no live increments
// can be overwritten while the saved counters are being loaded.
func (l *Inbound) RestoreStatistics(ctx context.Context) error {
	if l.statisticsStore == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("inbound runtime is closed")
	}
	if l.statisticsDone != nil {
		return nil
	}
	values, err := l.statisticsStore.LoadIngressStatistics(ctx)
	if err != nil {
		return err
	}
	if l.countersByID == nil {
		l.countersByID = make(map[string]*ingressCounters)
	}
	for id, value := range values {
		if existing := l.countersByID[id]; existing != nil {
			return errors.New("cannot restore statistics after inbound traffic has started")
		}
		counters := new(ingressCounters)
		counters.restore(value)
		l.countersByID[id] = counters
	}
	l.statisticsLastSaved = maps.Clone(values)
	l.statisticsDone = make(chan struct{})
	go l.runIngressStatistics()
	return nil
}

func (l *Inbound) runIngressStatistics() {
	defer close(l.statisticsDone)
	ticker := time.NewTicker(ingressStatisticsFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-ticker.C:
			if err := l.FlushStatistics(context.Background()); err != nil && !errors.Is(err, context.Canceled) {
				log.Warn("persist inbound ingress statistics failed", "err", err)
			}
		}
	}
}

// FlushStatistics collects changed snapshots without holding any request-path
// mutex or performing SQLite I/O for incoming packets, streams or pings.
func (l *Inbound) FlushStatistics(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("inbound runtime is closed")
	}
	return l.flushStatisticsLocked(ctx)
}

func (l *Inbound) flushStatisticsLocked(ctx context.Context) error {
	if l.statisticsStore == nil {
		return nil
	}
	changed := make(map[string]contract.IngressTotals)
	for id, counters := range l.countersByID {
		snapshot := counters.snapshot()
		if saved, ok := l.statisticsLastSaved[id]; !ok || saved != snapshot {
			changed[id] = snapshot
		}
	}
	if len(changed) == 0 {
		return nil
	}
	if err := l.statisticsStore.SaveIngressStatistics(ctx, changed); err != nil {
		return err
	}
	if l.statisticsLastSaved == nil {
		l.statisticsLastSaved = make(map[string]contract.IngressTotals)
	}
	maps.Copy(l.statisticsLastSaved, changed)
	return nil
}

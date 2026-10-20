package gateway

import (
	"context"
	"errors"
	"maps"
	"net"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/log"
)

const statisticsFlushInterval = 5 * time.Second

// StatisticsStore persists lifetime HTTP counters independently of Gateway
// configuration revisions and active backend health.
type StatisticsStore interface {
	LoadStatistics(context.Context) (map[string]contract.StatisticsTotals, error)
	SaveStatistics(context.Context, map[string]contract.StatisticsTotals) error
	ResetStatistics(context.Context, string) error
}

func (c *Counters) statistics() contract.StatisticsTotals {
	return contract.StatisticsTotals{
		Requests:         c.Requests.Load(),
		Blocked:          c.Blocked.Load(),
		Forwarded:        c.Forwarded.Load(),
		Errors:           c.Errors.Load(),
		TLSFailures:      c.TLSFailures.Load(),
		ProtocolFailures: c.ProtocolFailures.Load(),
		DurationNS:       c.DurationNS.Load(),
	}
}

func (c *Counters) restoreStatistics(v contract.StatisticsTotals) {
	c.Requests.Store(v.Requests)
	c.Blocked.Store(v.Blocked)
	c.Forwarded.Store(v.Forwarded)
	c.Errors.Store(v.Errors)
	c.TLSFailures.Store(v.TLSFailures)
	c.ProtocolFailures.Store(v.ProtocolFailures)
	c.DurationNS.Store(v.DurationNS)
}

func (m *Manager) runStatistics() {
	defer close(m.statisticsDone)
	ticker := time.NewTicker(statisticsFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.statisticsStop:
			return
		case <-ticker.C:
			if err := m.FlushStatistics(context.Background()); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Warn("flush gateway statistics failed", "err", err)
			}
		}
	}
}

// FlushStatistics only takes atomic snapshots. Requests never wait for SQLite.
// Management operations serialize with this flush so stale snapshots cannot
// resurrect deleted or reset counters.
func (m *Manager) FlushStatistics(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return net.ErrClosed
	}
	return m.flushStatisticsLocked(ctx)
}

func (m *Manager) flushStatisticsLocked(ctx context.Context) error {
	if m.statisticsStore == nil {
		return nil
	}
	s := m.current.Load()
	if s == nil {
		return nil
	}
	changed := make(map[string]contract.StatisticsTotals)
	for id, g := range s.gateways {
		value := g.engine.Counters.statistics()
		if saved, ok := m.persistedStatistics[id]; !ok || saved != value {
			changed[id] = value
		}
	}
	if len(changed) == 0 {
		return nil
	}
	if err := m.statisticsStore.SaveStatistics(ctx, changed); err != nil {
		return err
	}
	if m.persistedStatistics == nil {
		m.persistedStatistics = make(map[string]contract.StatisticsTotals)
	}
	maps.Copy(m.persistedStatistics, changed)
	return nil
}

// ResetStatistics clears one Gateway, or all Gateways if id is empty. The DB
// transaction commits before atomic counters are zeroed; failures preserve
// the current counters. Future requests can start counting immediately.
func (m *Manager) ResetStatistics(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return net.ErrClosed
	}
	s := m.current.Load()
	if s == nil {
		return net.ErrClosed
	}
	if id != "" {
		found := false
		for _, g := range s.config.Gateways {
			if g.ID == id {
				found = true
				break
			}
		}
		if !found {
			return errors.New("gateway not found")
		}
	}
	if m.statisticsStore != nil {
		if err := m.statisticsStore.ResetStatistics(ctx, id); err != nil {
			return err
		}
	}
	clearCounter := func(g *gatewayRuntime) {
		g.engine.Counters.restoreStatistics(contract.StatisticsTotals{})
	}
	if id == "" {
		for _, g := range s.gateways {
			clearCounter(g)
		}
		clear(m.persistedStatistics)
		clear(m.restoredStatistics)
	} else {
		if g := s.gateways[id]; g != nil {
			clearCounter(g)
		}
		delete(m.persistedStatistics, id)
		delete(m.restoredStatistics, id)
	}
	return nil
}

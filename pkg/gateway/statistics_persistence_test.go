package gateway

import (
	"context"
	"errors"
	"maps"
	"net/http/httptest"
	"sync"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
)

type memoryStatisticsStore struct {
	*memoryStore
	statisticsMu sync.Mutex
	statistics   map[string]contract.StatisticsTotals
	failWrite    bool
}

func (s *memoryStatisticsStore) LoadStatistics(context.Context) (map[string]contract.StatisticsTotals, error) {
	s.statisticsMu.Lock()
	defer s.statisticsMu.Unlock()
	values := make(map[string]contract.StatisticsTotals)
	maps.Copy(values, s.statistics)
	return values, nil
}

func (s *memoryStatisticsStore) SaveStatistics(_ context.Context, values map[string]contract.StatisticsTotals) error {
	s.statisticsMu.Lock()
	defer s.statisticsMu.Unlock()
	if s.failWrite {
		return errors.New("sqlite busy")
	}
	if s.statistics == nil {
		s.statistics = make(map[string]contract.StatisticsTotals)
	}
	maps.Copy(s.statistics, values)
	return nil
}

func (s *memoryStatisticsStore) ResetStatistics(_ context.Context, id string) error {
	s.statisticsMu.Lock()
	defer s.statisticsMu.Unlock()
	if s.failWrite {
		return errors.New("sqlite busy")
	}
	if id == "" {
		clear(s.statistics)
	} else {
		delete(s.statistics, id)
	}
	return nil
}

func blockedConfig() contract.Config {
	return contract.Config{Gateways: []contract.Gateway{
		{ID: "web", Name: "Web", Enabled: true, Default: contract.Action{Type: "block", Status: 204}},
		{ID: "api", Name: "API", Enabled: true, Default: contract.Action{Type: "block", Status: 204}},
	}}
}

func requestGateway(t *testing.T, m *Manager, id string) {
	t.Helper()
	g := m.current.Load().gateways[id]
	if g == nil {
		t.Fatalf("missing Gateway %s", id)
	}
	recorder := httptest.NewRecorder()
	g.engine.ServeHTTP(recorder, httptest.NewRequest("GET", "http://example.com/", nil))
	if recorder.Code != 204 {
		t.Fatalf("unexpected response %d", recorder.Code)
	}
}

func TestGatewayStatisticsRestartAndConfigReload(t *testing.T) {
	ctx := t.Context()
	store := &memoryStatisticsStore{memoryStore: &memoryStore{config: blockedConfig()}}
	m, err := NewManager(ctx, store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	requestGateway(t, m, "web")
	requestGateway(t, m, "web")
	if err := m.FlushStatistics(ctx); err != nil {
		t.Fatal(err)
	}
	saved, err := store.LoadStatistics(ctx)
	if err != nil || saved["web"].Requests != 2 {
		t.Fatalf("persisted requests=%+v error=%v", saved, err)
	}
	config := m.Config()
	config.Gateways[0].Name = "Updated"
	if _, err := m.Save(ctx, config); err != nil {
		t.Fatal(err)
	}
	if got := m.Status().Gateways[0].Requests; got != 2 {
		t.Fatalf("policy reload lost counters: %d", got)
	}
	requestGateway(t, m, "api")
	requestGateway(t, m, "web")
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := NewManager(ctx, store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	status := restarted.Status()
	if len(status.Gateways) != 2 || status.Gateways[0].Requests != 3 ||
		status.Gateways[0].Blocked != 3 || status.Gateways[1].Requests != 1 {
		t.Fatalf("restart lost cumulative counters: %+v", status.Gateways)
	}
}

func TestGatewayStatisticsResetAndFailedWrites(t *testing.T) {
	ctx := t.Context()
	store := &memoryStatisticsStore{memoryStore: &memoryStore{config: blockedConfig()}}
	m, err := NewManager(ctx, store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	requestGateway(t, m, "web")
	requestGateway(t, m, "api")
	if err := m.FlushStatistics(ctx); err != nil {
		t.Fatal(err)
	}
	store.failWrite = true
	if err := m.ResetStatistics(ctx, "web"); err == nil {
		t.Fatal("failed reset was accepted")
	}
	if m.Status().Gateways[0].Requests != 1 {
		t.Fatal("failed reset cleared live statistics")
	}
	requestGateway(t, m, "web")
	if err := m.FlushStatistics(ctx); err == nil {
		t.Fatal("failed flush was accepted")
	}
	store.failWrite = false
	if err := m.ResetStatistics(ctx, "missing"); err == nil {
		t.Fatal("reset accepted unknown gateway")
	}
	if err := m.ResetStatistics(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	if m.Status().Gateways[0].Requests != 0 || m.Status().Gateways[1].Requests != 1 {
		t.Fatal("reset cleared the wrong Gateway")
	}
	if err := m.FlushStatistics(ctx); err != nil {
		t.Fatal(err)
	}
	saved, err := store.LoadStatistics(ctx)
	if err != nil || saved["web"].Requests != 0 || saved["api"].Requests != 1 {
		t.Fatalf("periodic flush resurrected reset data: %+v %v", saved, err)
	}
	if err := m.ResetStatistics(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := m.FlushStatistics(ctx); err != nil {
		t.Fatal(err)
	}
	saved, err = store.LoadStatistics(ctx)
	if err != nil || saved["api"].Requests != 0 {
		t.Fatalf("global reset was not durable: %+v %v", saved, err)
	}
}

func TestGatewayStatisticsStartupRepairRestoresCounters(t *testing.T) {
	ctx := t.Context()
	config := blockedConfig()
	config.Gateways[0].TLSMode = "unsupported"
	store := &memoryStatisticsStore{
		memoryStore: &memoryStore{config: config},
		statistics: map[string]contract.StatisticsTotals{
			"web": {Requests: 17, Blocked: 14, DurationNS: 123456},
		},
	}
	m, err := NewManager(ctx, store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if m.Status().StartupError == "" {
		t.Fatal("expected a repairable startup failure")
	}
	next := m.Config()
	next.Gateways[0].TLSMode = "off"
	if _, err := m.Save(ctx, next); err != nil {
		t.Fatal(err)
	}
	if got := m.Status().Gateways[0]; got.Requests != 17 || got.DurationNS != 123456 {
		t.Fatalf("startup repair lost saved statistics: %+v", got)
	}
}

func TestGatewayStatisticsConcurrentRequestsAndFlush(t *testing.T) {
	ctx := t.Context()
	store := &memoryStatisticsStore{memoryStore: &memoryStore{config: blockedConfig()}}
	m, err := NewManager(ctx, store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				requestGateway(t, m, "web")
			}
		})
	}
	for range 12 {
		if err := m.FlushStatistics(ctx); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	if err := m.FlushStatistics(ctx); err != nil {
		t.Fatal(err)
	}
	got := m.Status().Gateways[0]
	saved, err := store.LoadStatistics(ctx)
	if err != nil || got.Requests != 800 || got.Blocked != 800 ||
		saved["web"].Requests != 800 {
		t.Fatalf("concurrent flush lost counts: %+v, saved=%+v error=%v", got, saved, err)
	}
}

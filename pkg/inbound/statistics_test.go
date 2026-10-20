package inbound

import (
	"context"
	"errors"
	"maps"
	"path/filepath"
	"sync"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func testIngressConfig(id string) contract.Inbound {
	return contract.Inbound{
		ID: id, Name: id, Enabled: true,
		Network:  contract.NewTypedNetwork(contract.TCPUDPNetwork{Host: "127.0.0.1:0", UDP: contract.UDPTCPOnly}),
		Protocol: contract.NewTypedProtocol(contract.MixedProtocol{}),
	}
}

func TestIngressStatisticsPersistAcrossReloadDisableRestartAndDelete(t *testing.T) {
	ctx := t.Context()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := plainstore.NewInboundStore(db.DB())
	if err := store.SaveSettings(ctx, plainstore.InboundSettings{}); err != nil {
		t.Fatal(err)
	}
	newRuntime := func() (*Inbound, *ContractStore) {
		t.Helper()
		runtime := NewInbound(netapi.NewErrProxy(errors.New("no outbound")), WithIngressStatisticsStore(store))
		if err := runtime.RestoreStatistics(ctx); err != nil {
			t.Fatal(err)
		}
		return runtime, NewContractStore(store, runtime)
	}
	runtime, controller := newRuntime()
	config := testIngressConfig("mixed")
	if err := controller.Save(ctx, config, 1); err != nil {
		t.Fatal(err)
	}
	counter := runtime.countersByID["mixed"]
	counter.streams.Add(17)
	counter.packets.Add(300)
	counter.pings.Add(5)
	if err := runtime.FlushStatistics(ctx); err != nil {
		t.Fatal(err)
	}
	// A listener reconfiguration must preserve the counter pointer and total.
	config.Name = "Renamed"
	if err := controller.Save(ctx, config, 2); err != nil {
		t.Fatal(err)
	}
	if runtime.countersByID["mixed"] != counter {
		t.Fatal("listener reconfiguration replaced cumulative counters")
	}
	counter.streams.Add(3)
	config.Enabled = false
	if err := controller.Save(ctx, config, 3); err != nil {
		t.Fatal(err)
	}
	statuses, err := controller.Statuses(ctx)
	if err != nil || len(statuses) != 1 {
		t.Fatalf("statuses=%+v error=%v", statuses, err)
	}
	status := statuses[0]
	if status.Status != "disabled" || status.Statistics.AcceptedStreams != "20" ||
		status.Statistics.ReceivedPackets != "300" || status.Statistics.ReceivedPings != "5" {
		t.Fatalf("disable lost counters: %+v", status)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	restored, contracts := newRuntime()
	defer restored.Close()
	if err := contracts.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	statuses, err = contracts.Statuses(ctx)
	if err != nil || len(statuses) != 1 || statuses[0].Statistics.AcceptedStreams != "20" {
		t.Fatalf("restart lost disabled inbound counts: %+v %v", statuses, err)
	}
	config.Enabled = true
	if err := contracts.Save(ctx, config, 4); err != nil {
		t.Fatal(err)
	}
	if got := restored.countersByID["mixed"].snapshot(); got != (contract.IngressTotals{
		AcceptedStreams: 20, ReceivedPackets: 300, ReceivedPings: 5,
	}) {
		t.Fatalf("reenabled ingress counters=%+v", got)
	}
	if err := contracts.Delete(ctx, "mixed"); err != nil {
		t.Fatal(err)
	}
	if _, ok := restored.countersByID["mixed"]; ok {
		t.Fatal("deleted inbound retained live statistics")
	}
	if err := contracts.Save(ctx, config, 5); err != nil {
		t.Fatal(err)
	}
	if got := restored.countersByID["mixed"].snapshot(); got != (contract.IngressTotals{}) {
		t.Fatalf("new inbound reused deleted totals: %+v", got)
	}
}

type failingIngressStore struct {
	mu        sync.Mutex
	values    map[string]contract.IngressTotals
	failWrite bool
	failRead  bool
}

func (s *failingIngressStore) LoadIngressStatistics(context.Context) (map[string]contract.IngressTotals, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failRead {
		return nil, errors.New("read failed")
	}
	values := make(map[string]contract.IngressTotals)
	maps.Copy(values, s.values)
	return values, nil
}

func (s *failingIngressStore) SaveIngressStatistics(_ context.Context, values map[string]contract.IngressTotals) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWrite {
		return errors.New("write failed")
	}
	if s.values == nil {
		s.values = make(map[string]contract.IngressTotals)
	}
	maps.Copy(s.values, values)
	return nil
}

func TestIngressStatisticsFlushFailureRetryAndConcurrentIncrements(t *testing.T) {
	store := &failingIngressStore{failWrite: true}
	runtime := NewInbound(netapi.NewErrProxy(errors.New("unused")), WithIngressStatisticsStore(store))
	defer runtime.Close()
	if err := runtime.RestoreStatistics(t.Context()); err != nil {
		t.Fatal(err)
	}
	counter := new(ingressCounters)
	runtime.mu.Lock()
	runtime.countersByID["local"] = counter
	runtime.mu.Unlock()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 1000 {
				counter.packets.Add(1)
			}
		})
	}
	if err := runtime.FlushStatistics(t.Context()); err == nil {
		t.Fatal("failed write should be reported")
	}
	wg.Wait()
	store.mu.Lock()
	store.failWrite = false
	store.mu.Unlock()
	if err := runtime.FlushStatistics(t.Context()); err != nil {
		t.Fatal(err)
	}
	saved, err := store.LoadIngressStatistics(t.Context())
	if err != nil || saved["local"].ReceivedPackets != 8000 {
		t.Fatalf("failed write lost increments: %+v %v", saved, err)
	}
}

func TestIngressStatisticsRestoreFailureDoesNotStartWriter(t *testing.T) {
	store := &failingIngressStore{failRead: true}
	runtime := NewInbound(netapi.NewErrProxy(errors.New("unused")), WithIngressStatisticsStore(store))
	defer runtime.Close()
	if err := runtime.RestoreStatistics(t.Context()); err == nil || runtime.statisticsDone != nil {
		t.Fatal("failed restore started statistics persistence")
	}
}

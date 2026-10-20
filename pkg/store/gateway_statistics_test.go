package store

import (
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
)

func TestGatewayStatisticsSQLiteRestoreResetAndDelete(t *testing.T) {
	editor, _, _ := editorStore(t)
	ctx := t.Context()
	store := NewGatewayStore(editor.db)
	config, err := store.Save(ctx, contract.Config{Gateways: []contract.Gateway{
		{ID: "web", Name: "web", Default: contract.Action{Type: "block"}},
		{ID: "api", Name: "api", Default: contract.Action{Type: "block"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	first := contract.StatisticsTotals{
		Requests: 100, Blocked: 30, Forwarded: 55, Errors: 4,
		TLSFailures: 2, ProtocolFailures: 1, DurationNS: 500,
	}
	if err := store.SaveStatistics(ctx, map[string]contract.StatisticsTotals{
		"web": first, "api": {Requests: 4},
	}); err != nil {
		t.Fatal(err)
	}
	loaded, err := NewGatewayStore(editor.db).LoadStatistics(ctx)
	if err != nil || loaded["web"] != first || loaded["api"].Requests != 4 {
		t.Fatalf("reload=%+v error=%v", loaded, err)
	}
	// Absolute snapshots must be idempotent, not summed on retry.
	if err := store.SaveStatistics(ctx, map[string]contract.StatisticsTotals{"web": first}); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.LoadStatistics(ctx)
	if err != nil || loaded["web"] != first {
		t.Fatalf("duplicate flush accumulated values: %+v %v", loaded, err)
	}
	if err := store.ResetStatistics(ctx, "api"); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.LoadStatistics(ctx)
	if err != nil || len(loaded) != 1 {
		t.Fatalf("per-gateway reset: %+v %v", loaded, err)
	}
	// Removing the owning Gateway deletes its counters atomically.
	config.Gateways = config.Gateways[1:]
	if _, err := store.Save(ctx, config); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.LoadStatistics(ctx)
	if err != nil || len(loaded) != 0 {
		t.Fatalf("deleted Gateway retained statistics: %+v %v", loaded, err)
	}
	if err := store.SaveStatistics(ctx, map[string]contract.StatisticsTotals{"api": {Requests: 7}}); err != nil {
		t.Fatal(err)
	}
	if err := store.ResetStatistics(ctx, ""); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.LoadStatistics(ctx)
	if err != nil || len(loaded) != 0 {
		t.Fatalf("global reset: %+v %v", loaded, err)
	}
}

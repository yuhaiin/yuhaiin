package store

import (
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
)

func TestInboundIngressStatisticsPersistAcrossUpsertsAndDelete(t *testing.T) {
	editor, _, _ := editorStore(t)
	ctx := t.Context()
	store := NewInboundStore(editor.db)
	makeInbound := func(id string) contract.Inbound {
		return contract.Inbound{
			ID: id, Name: id, Enabled: false,
			Network:  contract.NewTypedNetwork(contract.TCPUDPNetwork{Host: "127.0.0.1:0", UDP: contract.UDPTCPOnly}),
			Protocol: contract.NewTypedProtocol(contract.MixedProtocol{}),
		}
	}
	for _, id := range []string{"a", "b"} {
		if err := store.Save(ctx, makeInbound(id), 1); err != nil {
			t.Fatal(err)
		}
	}
	value := contract.IngressTotals{AcceptedStreams: 17, ReceivedPackets: 123, ReceivedPings: 8}
	original := map[string]contract.IngressTotals{
		"a": value, "b": {AcceptedStreams: 9},
		"removed": {AcceptedStreams: 1},
	}
	if err := store.SaveIngressStatistics(ctx, original); err != nil {
		t.Fatal(err)
	}
	loaded, err := NewInboundStore(editor.db).LoadIngressStatistics(ctx)
	if err != nil || len(loaded) != 2 || loaded["a"] != value || loaded["b"].AcceptedStreams != 9 {
		t.Fatalf("loaded=%+v, err=%v", loaded, err)
	}
	if err := store.SaveIngressStatistics(ctx, original); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.LoadIngressStatistics(ctx)
	if err != nil || loaded["a"] != value {
		t.Fatalf("absolute snapshot was double-counted: %+v %v", loaded, err)
	}
	if err := store.Delete(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.LoadIngressStatistics(ctx)
	if err != nil || len(loaded) != 1 || loaded["b"].AcceptedStreams != 9 {
		t.Fatalf("deleted inbound retained statistics: %+v %v", loaded, err)
	}
	// A late writer must not recreate statistics for an absent inbound.
	if err := store.SaveIngressStatistics(ctx, map[string]contract.IngressTotals{"a": value}); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, makeInbound("a"), 2); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.LoadIngressStatistics(ctx)
	if err != nil || len(loaded) != 1 {
		t.Fatalf("recreated inbound inherited deleted totals: %+v %v", loaded, err)
	}
}

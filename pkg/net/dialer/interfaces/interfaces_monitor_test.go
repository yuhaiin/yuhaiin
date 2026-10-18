package interfaces

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestNetworkStateDiff(t *testing.T) {
	addresses := map[netip.Addr]string{
		netip.MustParseAddr("192.0.2.5"):   "en0",
		netip.MustParseAddr("2001:db8::5"): "en0",
		netip.MustParseAddr("10.10.0.1"):   "utun0",
	}
	routes := router{v4: []rtInfo{
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), OutputIface: "en0", Gateway: netip.MustParseAddr("192.0.2.1")},
		{Dst: netip.MustParsePrefix("10.10.0.0/16"), OutputIface: "utun0"},
	}}
	baseline := snapshotNetwork("en0", addresses, routes)
	if networkStateChanged(baseline, snapshotNetwork("en0", addresses, routes)) {
		t.Fatal("unchanged state should not notify")
	}

	// Unrelated tunnel route and address churn refreshes the route trie,
	// but should not force expensive DNS reconfiguration on en0.
	addresses[netip.MustParseAddr("10.10.0.2")] = "utun0"
	routes.v4[1].Dst = netip.MustParsePrefix("10.11.0.0/16")
	if networkStateChanged(baseline, snapshotNetwork("en0", addresses, routes)) {
		t.Fatal("unrelated interface changes should not notify DNS")
	}

	addresses[netip.MustParseAddr("192.0.2.6")] = "en0"
	if !networkStateChanged(baseline, snapshotNetwork("en0", addresses, routes)) {
		t.Fatal("address change on same interface must notify")
	}
	delete(addresses, netip.MustParseAddr("192.0.2.6"))

	routes.v4[0].Gateway = netip.MustParseAddr("192.0.2.254")
	if !networkStateChanged(baseline, snapshotNetwork("en0", addresses, routes)) {
		t.Fatal("gateway change on same interface must notify")
	}
	if !networkStateChanged(baseline, snapshotNetwork("", addresses, routes)) {
		t.Fatal("loss of default interface must notify")
	}
	if !networkStateChanged(baseline, snapshotNetwork("en1", addresses, routes)) {
		t.Fatal("default interface switch must notify")
	}
}

func TestRunNetworkMonitorCoalescesEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan string, 16)
	calls := make(chan string, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runNetworkMonitor(ctx, events, func(reason string) error {
			calls <- reason
			return nil
		}, 20*time.Millisecond, 100*time.Millisecond, time.Hour)
	}()
	for i := 0; i < 10; i++ {
		events <- "route"
	}
	select {
	case reason := <-calls:
		if reason != "route" {
			t.Fatalf("unexpected reason: %s", reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("debounced refresh did not run")
	}
	select {
	case <-calls:
		t.Fatal("identical burst should be coalesced")
	case <-time.After(80 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("monitor did not stop")
	}
}

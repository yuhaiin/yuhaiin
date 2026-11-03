package tailscale

import (
	"net/netip"
	"testing"

	"tailscale.com/tsnet"
)

func TestStackDiagnosticDoesNotStartOrWaitForTailnet(t *testing.T) {
	client := &Tailscale{}
	client.mu.Lock()
	busy := client.StackDiagnostic(32)
	client.mu.Unlock()
	if busy.MTU != 0 {
		t.Fatalf("busy tailnet: %+v", busy)
	}
	if got := client.StackDiagnostic(32); got.MTU != 0 || client.tsnet != nil {
		t.Fatalf("unstarted tailnet: %+v", got)
	}
	tun := newTailnetTun()
	t.Cleanup(func() { _ = tun.Close() })
	client.tsnet = &tsnet.Server{Tun: tun}
	if got := client.StackDiagnostic(32); got.MTU != 0 {
		t.Fatalf("unassigned tailnet: %+v", got)
	}
	if err := tun.configure(netip.MustParseAddr("100.64.0.1"), netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if got := client.StackDiagnostic(32); got.MTU != 1280 {
		t.Fatalf("assigned tailnet: %+v", got)
	}
	client.closed = true
	if got := client.StackDiagnostic(32); got.MTU != 0 {
		t.Fatalf("closed tailnet: %+v", got)
	}
}

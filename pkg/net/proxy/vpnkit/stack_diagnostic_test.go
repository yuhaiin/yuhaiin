package vpnkit

import (
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
)

func TestStackDiagnosticUsesExistingStack(t *testing.T) {
	network, err := wireguard.CreateLightweightNetTUN([]netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}, 1300)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = network.Close() })
	for _, active := range []bool{false, true} {
		client := &Client{}
		if active {
			client.network = network
		}
		provider, ok := any(client).(lightweight.DiagnosticProvider)
		if !ok {
			t.Fatalf("%T hides its lightweight stack", client)
		}
		got := provider.StackDiagnostic(0)
		if active && (got.MTU != 1300 || len(got.Flows) != 0) {
			t.Fatalf("active snapshot: %+v", got)
		}
		if !active && got.MTU != 0 {
			t.Fatalf("inactive snapshot: %+v", got)
		}
	}
}

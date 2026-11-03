//go:build (((linux && !android) || darwin) && (amd64 || arm64)) || (windows && amd64) || (android && arm64 && cgo)

package zerotier

import (
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
)

func TestStackDiagnosticFollowsControllerAssignment(t *testing.T) {
	client := &Client{}
	if got := client.StackDiagnostic(32); got.MTU != 0 {
		t.Fatalf("unassigned network: %+v", got)
	}
	network, err := wireguard.CreateLightweightNetTUN([]netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}, 1400)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = network.Close() })
	client.active = &session{tun: network}
	if got := client.StackDiagnostic(32); got.MTU != 1400 {
		t.Fatalf("assigned network: %+v", got)
	}
	client.active = nil
	if got := client.StackDiagnostic(32); got.MTU != 0 {
		t.Fatalf("revoked assignment: %+v", got)
	}
}

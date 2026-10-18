//go:build (!linux || android) && !darwin && !windows

package interfaces

import (
	"net"
	"net/netip"
	"testing"
)

func TestReconcileWithoutDefaultRouteSupport(t *testing.T) {
	oldInterfaces := AltNetInterfaces
	oldName := defaultInterfaceName.Load()
	oldState := lastNetworkState.Load()
	oldAddresses := localAddresses.Load()
	oldRouter := defaultrouter.Load()
	t.Cleanup(func() {
		AltNetInterfaces = oldInterfaces
		defaultInterfaceName.Store(oldName)
		lastNetworkState.Store(oldState)
		localAddresses.Store(oldAddresses)
		defaultrouter.Store(oldRouter)
	})

	AltNetInterfaces = func() ([]Interface, error) {
		return []Interface{{
			Interface: &net.Interface{Name: "wlan0", Index: 1},
			AltAddrs: []net.Addr{&net.IPNet{
				IP: net.IPv4(192, 0, 2, 5), Mask: net.CIDRMask(24, 32),
			}},
		}}, nil
	}
	for _, name := range []string{"", "wlan0"} {
		t.Run(name, func(t *testing.T) {
			SetDefaultInterfaceName(name)
			localAddresses.Store(nil)
			if err := reGetDefaultInterface("startup"); err != nil {
				t.Fatalf("unsupported route discovery must not trigger retries: %v", err)
			}
			if got := DefaultInterfaceName(); got != name {
				t.Fatalf("configured interface changed: got %q, want %q", got, name)
			}
			addresses := localAddresses.Load()
			if addresses == nil || (*addresses)[netip.MustParseAddr("192.0.2.5")] != "wlan0" {
				t.Fatal("interface addresses were not refreshed")
			}
		})
	}
}

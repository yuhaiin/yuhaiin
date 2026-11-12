package wireguard

import (
	"context"
	"net/netip"
	"testing"
)

func TestPeerUnderlayChoosesCoordinatorAddress(t *testing.T) {
	v6 := netip.MustParseAddrPort("[2001:db8::1]:51821")
	v4 := netip.MustParseAddrPort("192.0.2.1:51821")
	moved := netip.MustParseAddrPort("192.0.2.2:51821")
	peer4, peer6 := netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("2001:db8::7")
	for _, tc := range []struct {
		name     string
		current  netip.AddrPort
		resolved []netip.AddrPort
		answered bool
		peer     netip.Addr
		want     netip.AddrPort
	}{
		{"host without IPv6 tries IPv4", v6, []netip.AddrPort{v6, v4}, false, netip.Addr{}, v4},
		{"host without IPv4 returns to IPv6", v4, []netip.AddrPort{v6, v4}, false, netip.Addr{}, v6},
		{"single address has no alternative", v4, []netip.AddrPort{v4}, false, netip.Addr{}, v4},
		{"an outage keeps a working family", v6, []netip.AddrPort{v6, v4}, true, netip.Addr{}, v6},
		{"an outage follows a moved server", v4, []netip.AddrPort{moved}, true, netip.Addr{}, moved},
		{"IPv6 side follows an IPv4 partner", v6, []netip.AddrPort{v6, v4}, true, peer4, v4},
		{"IPv4 side waits for an IPv6 partner", v4, []netip.AddrPort{v6, v4}, true, peer6, v4},
		{"partner family is unavailable", v6, []netip.AddrPort{v6}, true, peer4, v6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rebinds := 0
			u := &peerUnderlay{
				candidates: []netip.AddrPort{v6, v4}, current: tc.current,
				resolve: func(context.Context) ([]netip.AddrPort, error) { return tc.resolved, nil },
				rebind:  func() { rebinds++ },
			}
			if tc.current == v4 {
				u.index = 1
			}
			u.refresh(tc.current, tc.answered, tc.peer)
			if got := u.candidates[u.index]; got != tc.want {
				t.Fatalf("next address %v, want %v", got, tc.want)
			}
			if want := tc.want != tc.current; (rebinds == 1) != want {
				t.Fatalf("%d socket replacements, want replacement: %v", rebinds, want)
			}
			// The socket that reported the problem is gone after a replacement.
			u.refresh(netip.MustParseAddrPort("203.0.113.1:1"), false, netip.Addr{})
			if rebinds > 1 {
				t.Fatal("a closed socket replaced its successor")
			}
		})
	}
}

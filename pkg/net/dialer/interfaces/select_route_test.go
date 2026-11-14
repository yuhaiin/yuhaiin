package interfaces

import (
	"net/netip"
	"testing"
)

func TestSelectRoute(t *testing.T) {
	r := router{
		v4: []rtInfo{
			{Dst: netip.MustParsePrefix("0.0.0.0/0"), OutputIface: "wifi", Metric: 55},
			{Dst: netip.MustParsePrefix("0.0.0.0/0"), OutputIface: "ethernet", Metric: 25},
			{Dst: netip.MustParsePrefix("0.0.0.0/1"), OutputIface: "tun0"},
			{Dst: netip.MustParsePrefix("128.0.0.0/1"), OutputIface: "tun0"},
			{Dst: netip.MustParsePrefix("192.168.20.0/24"), OutputIface: "wifi", Metric: 55},
			{Dst: netip.MustParsePrefix("10.8.0.0/16"), OutputIface: "wg0", Metric: 5},
		},
		v6: []rtInfo{
			{Dst: netip.MustParsePrefix("::/0"), OutputIface: "ethernet", Metric: 25},
			{Dst: netip.MustParsePrefix("::/1"), OutputIface: "tun0"},
		},
	}
	own := func(name string) bool { return name == "tun0" }
	for _, tc := range []struct {
		dst, want string
		exclude   func(string) bool
	}{
		// Without exclusion the TUN's /1 is the most specific.
		{"8.8.8.8", "tun0", nil},
		// Excluding our TUN: default routes, lowest metric wins (Windows).
		{"8.8.8.8", "ethernet", own},
		{"2001:4860::8888", "ethernet", own},
		// A more specific route beats metrics.
		{"192.168.20.9", "wifi", own},
		// Other VPNs are not excluded.
		{"10.8.1.1", "wg0", own},
		{"::ffff:8.8.8.8", "ethernet", own},
	} {
		got, ok := r.selectRoute(netip.MustParseAddr(tc.dst), tc.exclude)
		if !ok || got.Interface != tc.want {
			t.Errorf("%s = %+v %v, want %s", tc.dst, got, ok, tc.want)
		}
	}
	if _, ok := r.selectRoute(netip.MustParseAddr("8.8.8.8"), func(string) bool { return true }); ok {
		t.Error("everything excluded still matched")
	}
	defaults := r.defaults()
	if len(defaults) != 3 {
		t.Fatalf("defaults = %+v", defaults)
	}
}

// macOS: a LAN known only as an interface-scoped attached network is reached
// through that interface; scoped routes never replace a more specific global
// one and never act as a default.
func TestSelectRouteScopedAttachedNetwork(t *testing.T) {
	r := router{
		v4: []rtInfo{
			{Dst: netip.MustParsePrefix("0.0.0.0/0"), OutputIface: "en0"},
			{Dst: netip.MustParsePrefix("10.1.2.0/24"), OutputIface: "en0"},
		},
		scoped: []rtInfo{
			{Dst: netip.MustParsePrefix("192.168.20.0/24"), OutputIface: "en5"},
			{Dst: netip.MustParsePrefix("10.1.0.0/16"), OutputIface: "en5"},
			{Dst: netip.MustParsePrefix("192.168.30.0/24"), OutputIface: "utun4"},
		},
	}
	own := func(name string) bool { return name == "utun4" }
	for dst, want := range map[string]string{
		"192.168.20.9": "en5",
		"10.1.2.3":     "en0", // global /24 is more specific than scoped /16
		"10.1.9.9":     "en5",
		"8.8.8.8":      "en0",
		"192.168.30.1": "en0", // our TUN's scoped network is excluded
	} {
		got, ok := r.selectRoute(netip.MustParseAddr(dst), own)
		if !ok || got.Interface != want {
			t.Errorf("%s = %+v, want %s", dst, got, want)
		}
	}
}

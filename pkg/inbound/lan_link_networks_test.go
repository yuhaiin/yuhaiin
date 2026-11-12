package inbound

import (
	"net"
	"net/netip"
	"testing"
)

func TestClassifyLANNetworksFiltersUnrelatedInterfaces(t *testing.T) {
	up := net.FlagUp | net.FlagBroadcast
	got := classifyLANNetworks([]interfaceNetwork{
		{"eth0", up, netip.MustParsePrefix("192.168.50.7/24")},
		{"eth0", up, netip.MustParsePrefix("192.168.50.8/24")}, // duplicate network
		{"eth0", up, netip.MustParsePrefix("fe80::1/64")},      // link-local
		{"eth0", up, netip.MustParsePrefix("fd00:1234::5/64")},
		{"eth0", up, netip.MustParsePrefix("10.1.1.1/32")}, // host route
		{"lo", up | net.FlagLoopback, netip.MustParsePrefix("127.0.0.1/8")},
		{"wg0", up | net.FlagPointToPoint, netip.MustParsePrefix("10.8.0.2/24")},
		{"tailscale0", up, netip.MustParsePrefix("100.64.0.1/10")},
		{"docker0", up, netip.MustParsePrefix("172.17.0.1/16")},
		{"eth1", 0, netip.MustParsePrefix("192.168.9.2/24")}, // down
	})
	var cidrs []string
	for _, n := range got {
		cidrs = append(cidrs, n.CIDR)
	}
	if len(cidrs) != 2 || cidrs[0] != "192.168.50.0/24" || cidrs[1] != "fd00:1234::/64" {
		t.Fatalf("candidates = %v", cidrs)
	}
	if got[0].Family != "ipv4" || got[1].Family != "ipv6" {
		t.Fatalf("families: %+v", got)
	}
}

func TestDetectLANLinkNetworksReportsSupport(t *testing.T) {
	result := detectLANLinkNetworks()
	if result.Items == nil || (!result.Supported && result.Reason == "") {
		t.Fatalf("unsupported detection must explain itself: %+v", result)
	}
}

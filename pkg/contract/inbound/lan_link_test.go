package inbound

import (
	"net/netip"
	"slices"
	"testing"
)

func TestLANLinkGatewayGeneratesStableSubnetAndSecrets(t *testing.T) {
	g := LANLinkGateway{Networks: []string{"192.168.50.0/24", "10.0.0.0/8"}}
	if err := g.FillDefaults(); err != nil {
		t.Fatal(err)
	}
	pool := netip.MustParsePrefix(g.Subnet)
	if !pool.Addr().Is4() || pool.Bits() != 22 || pool.Overlaps(netip.MustParsePrefix("10.0.0.0/8")) ||
		pool.Overlaps(netip.MustParsePrefix("192.168.50.0/24")) || g.PrivateKey == "" {
		t.Fatalf("generated %+v", g)
	}
	subnet, key := g.Subnet, g.PrivateKey
	g.Networks = append(g.Networks, "192.168.51.0/24")
	if err := g.FillDefaults(); err != nil || g.Subnet != subnet || g.PrivateKey != key {
		t.Fatalf("regenerated state: %+v, %v", g, err)
	}
}

func TestLANLinkGatewayClientsHaveIndependentCredentials(t *testing.T) {
	g := LANLinkGateway{Networks: []string{"fd00:1234::/64"}}
	if err := g.FillDefaults(); err != nil {
		t.Fatal(err)
	}
	if pool := netip.MustParsePrefix(g.Subnet6); !pool.Addr().Is6() || pool.Overlaps(netip.MustParsePrefix("fd00:1234::/64")) {
		t.Fatalf("IPv6 subnet = %s", g.Subnet6)
	}
	a, err := g.AddClient(1, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := g.AddClient(2, "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Slot == b.Slot || a.Token == b.Token || a.Registration == b.Registration || a.ID == b.ID ||
		a.Registration == a.Token || a.PairingID() == b.PairingID() {
		t.Fatalf("clients share state: %+v %+v", a, b)
	}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	_, ips, err := g.Addresses(b.Slot)
	if err != nil || len(ips) != 2 || !netip.MustParsePrefix(g.Subnet).Contains(ips[0]) || !netip.MustParsePrefix(g.Subnet6).Contains(ips[1]) {
		t.Fatalf("addresses = %v, %v", ips, err)
	}
}

func TestLANLinkGatewayDualStack(t *testing.T) {
	g := LANLinkGateway{Networks: []string{"192.168.1.0/24", "fd00:1234::/64"}}
	if err := g.FillDefaults(); err != nil {
		t.Fatal(err)
	}
	v4, v6 := netip.MustParsePrefix(g.Subnet), netip.MustParsePrefix(g.Subnet6)
	if !v4.Addr().Is4() || !v6.Addr().Is6() {
		t.Fatalf("subnets = %s, %s", g.Subnet, g.Subnet6)
	}
	client, err := g.AddClient(1, "")
	if err != nil {
		t.Fatal(err)
	}
	gateway, ips, err := g.Addresses(client.Slot)
	if err != nil || len(gateway) != 2 || !v4.Contains(gateway[0]) || !v6.Contains(gateway[1]) || !v4.Contains(ips[0]) || !v6.Contains(ips[1]) {
		t.Fatalf("addresses = %v %v, %v", gateway, ips, err)
	}
}

func TestLANLinkGatewayMovesLegacyIPv6Subnet(t *testing.T) {
	g := LANLinkGateway{Networks: []string{"fd00:1234::/64"}}
	if err := g.FillDefaults(); err != nil {
		t.Fatal(err)
	}
	legacy := g.Subnet6
	g.Subnet, g.Subnet6 = legacy, ""
	// A configuration saved before dual-stack tunnels still runs.
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := g.FillDefaults(); err != nil || g.Subnet6 != legacy || !netip.MustParsePrefix(g.Subnet).Addr().Is4() {
		t.Fatalf("migrated %+v, %v", g, err)
	}
}

func TestLANLinkGatewayRejectsUnsafeNetworks(t *testing.T) {
	for _, networks := range [][]string{
		nil, {"127.0.0.0/8"}, {"169.254.0.0/16"}, {"224.0.0.0/4"}, {"0.0.0.0/0"}, {"192.168.1.5/24"},
		{"not a cidr"},
	} {
		g := LANLinkGateway{Networks: networks}
		if err := g.FillDefaults(); err == nil {
			t.Errorf("accepted networks %v", networks)
		}
	}
}

func TestLANLinkGatewaySubnetIsKeptForExistingClients(t *testing.T) {
	g := LANLinkGateway{Networks: []string{"192.168.50.0/24"}}
	if err := g.FillDefaults(); err != nil {
		t.Fatal(err)
	}
	if _, err := g.AddClient(1, ""); err != nil {
		t.Fatal(err)
	}
	// A network overlapping the live subnet is an error instead of silently
	// renumbering the clients.
	g.Networks = []string{g.Subnet}
	if err := g.FillDefaults(); err == nil {
		t.Fatal("overlapping network accepted while clients exist")
	}
	// Without clients the subnet may move out of the way.
	g.Clients = nil
	if err := g.FillDefaults(); err == nil && slices.Contains(g.Networks, g.Subnet) {
		t.Fatalf("subnet still overlaps: %+v", g)
	}
}

func TestLANLinkGatewayPoolExhaustion(t *testing.T) {
	g := LANLinkGateway{Networks: []string{"192.168.50.0/24"}}
	if err := g.FillDefaults(); err != nil {
		t.Fatal(err)
	}
	for range 1021 {
		if _, err := g.AddClient(1, ""); err != nil {
			return
		}
	}
	if _, err := g.AddClient(1, ""); err == nil {
		t.Fatal("address pool never reported full")
	}
}

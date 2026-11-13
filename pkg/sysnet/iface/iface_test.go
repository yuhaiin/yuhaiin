package iface

import (
	"net"
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
)

func TestClassify(t *testing.T) {
	for _, tt := range []struct {
		ifc  net.Interface
		hint string
		want string
	}{
		{net.Interface{Name: "lo", Flags: net.FlagLoopback}, "", TypeLoopback},
		{net.Interface{Name: "tailscale0"}, "", TypeTunnel},
		{net.Interface{Name: "wg0"}, "", TypeTunnel},
		{net.Interface{Name: "utun4", Flags: net.FlagPointToPoint}, "", TypeTunnel},
		{net.Interface{Name: "weird", Flags: net.FlagPointToPoint}, "", TypeTunnel},
		{net.Interface{Name: "en0", HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1}}, "", TypeEthernet},
		{net.Interface{Name: "wlp3s0"}, "", TypeWiFi},
		{net.Interface{Name: "docker0"}, "", TypeBridge},
		{net.Interface{Name: "veth12"}, "", TypeVirtual},
		{net.Interface{Name: "eth0"}, TypeWiFi, TypeWiFi},
		{net.Interface{Name: "x"}, "", TypeOther},
	} {
		if got := classify(tt.ifc, tt.hint); got != tt.want {
			t.Errorf("%s = %s, want %s", tt.ifc.Name, got, tt.want)
		}
	}
}

func TestGatewayRules(t *testing.T) {
	eth := Info{Name: "eth0", Type: TypeEthernet, Addresses: []netip.Prefix{netip.MustParsePrefix("192.168.1.20/24"), netip.MustParsePrefix("2001:db8:1::20/64")}}
	if !eth.NeedsGateway() {
		t.Fatal("ethernet routes need a gateway")
	}
	for gw, want := range map[string]bool{"192.168.1.1": true, "192.168.2.1": false, "192.168.1.20": false, "fe80::1": true, "2001:db8:1::1": true, "2001:db8:2::1": false} {
		if got := eth.OnLink(netip.MustParseAddr(gw)); got != want {
			t.Errorf("OnLink(%s) = %v, want %v", gw, got, want)
		}
	}
	wg := Info{Name: "wg0", Type: TypeTunnel, Addresses: []netip.Prefix{netip.MustParsePrefix("10.8.0.2/32")}}
	if wg.NeedsGateway() || !wg.HasFamily(false) || wg.HasFamily(true) {
		t.Fatal("tunnel gateway/family rules")
	}
	linkLocalOnly := Info{Addresses: []netip.Prefix{netip.MustParsePrefix("fe80::1/64")}}
	if linkLocalOnly.HasFamily(true) {
		t.Fatal("link-local address counted as IPv6 connectivity")
	}
}

func TestFindByNameOrHardwareAddress(t *testing.T) {
	list := []Info{{Name: "eth0", Index: 2, HardwareAddr: "02:00:00:00:00:01"}, {Name: "wg0", Index: 5}}
	if i, ok := Find(list, "wg0", ""); !ok || i.Index != 5 {
		t.Fatal("name lookup")
	}
	if i, ok := Find(list, "enp1s0", "02:00:00:00:00:01"); !ok || i.Name != "eth0" {
		t.Fatal("renamed interface not found by hardware address")
	}
	if _, ok := Find(list, "missing", ""); ok {
		t.Fatal("missing interface found")
	}
}

func TestListCurrentInterfaces(t *testing.T) {
	list, err := List()
	if err != nil {
		t.Fatal(err)
	}
	loopback := false
	for _, i := range list {
		if i.Type == TypeLoopback {
			loopback = true
		}
		if i.Index <= 0 || i.Name == "" {
			t.Fatalf("invalid interface %+v", i)
		}
	}
	if !loopback {
		t.Fatal("loopback interface not discovered")
	}
}

// Android 11+ denies the netlink dumps net.Interfaces uses; the app supplies
// the list instead and List must use it.
func TestListUsesPlatformInterfaceSource(t *testing.T) {
	previous := interfaces.AltNetInterfaces
	t.Cleanup(func() { interfaces.AltNetInterfaces = previous })
	interfaces.AltNetInterfaces = func() ([]interfaces.Interface, error) {
		return []interfaces.Interface{
			{Interface: &net.Interface{Name: "wlan0", Index: 30, MTU: 1500, Flags: net.FlagUp | net.FlagBroadcast},
				AltAddrs: []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.1.20"), Mask: net.CIDRMask(24, 32)}}},
			{Interface: &net.Interface{Name: "tun0", Index: 31, MTU: 1500, Flags: net.FlagUp | net.FlagPointToPoint}, AltAddrs: []net.Addr{}},
		}, nil
	}
	list, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Name != "wlan0" || list[0].Type != TypeWiFi || list[0].Addresses[0] != netip.MustParsePrefix("192.168.1.20/24") ||
		list[1].Type != TypeTunnel || len(list[1].Addresses) != 0 {
		t.Fatalf("list = %+v", list)
	}
}

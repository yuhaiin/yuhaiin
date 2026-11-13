package tun

import (
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
)

func TestCheckTunName(t *testing.T) {
	t.Log(checkTunName(netlink.TunScheme{
		Scheme: "tun",
		Name:   "tun0",
	}))
}

func TestTunLinkReportsDeviceWithoutRoutes(t *testing.T) {
	options := &netlink.Options{Interface: netlink.TunScheme{Scheme: "tun", Name: "utun8"}, Index: 9,
		Inet4Address:   []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
		RequiredRoutes: []netip.Prefix{netip.MustParsePrefix("172.19.0.0/30")}}
	link := (&tunAccepter{options: options}).TunLink()
	if link.Name != "utun8" || link.Index != 9 || link.IPv4 != netip.MustParsePrefix("172.19.0.1/30") || link.IPv6.IsValid() {
		t.Fatalf("link = %+v", link)
	}
	link.RequiredRoutes[0] = netip.Prefix{}
	if !options.RequiredRoutes[0].IsValid() {
		t.Fatal("link aliases the device options")
	}
}

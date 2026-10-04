package tun

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
)

func TestCheckTunName(t *testing.T) {
	t.Log(checkTunName(netlink.TunScheme{
		Scheme: "tun",
		Name:   "tun0",
	}))
}

func TestToRoutesFileAndHosts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.txt")
	if err := os.WriteFile(path, []byte("198.18.0.1/16\n2001:2::1\ninvalid\n198.18.1.0/24\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got := toRoutes([]string{"file:" + path, "198.18.0.0/16", "192.0.2.1", "bad", "file:"})
	want := []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("198.18.0.0/16"), netip.MustParsePrefix("2001:2::1/128")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestEffectiveFakeIPRoutes(t *testing.T) {
	previousIPv6 := configuration.IPv6.Load()
	configuration.IPv6.Store(true)
	defer configuration.IPv6.Store(previousIPv6)
	options := &netlink.Options{Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/24")}, Inet6Address: []netip.Prefix{netip.MustParsePrefix("fd00::1/64")}}
	ranges := [2]netip.Prefix{netip.MustParsePrefix("198.18.0.0/16"), netip.MustParsePrefix("2001:2::/64")}
	users := toRoutes([]string{"198.18.0.0/24", "192.0.2.0/24"})
	original := slices.Clone(users)
	got := effectiveRoutes(options, users, true, ranges)
	want := toRoutes([]string{"192.0.2.0/24", "198.18.0.0/16", "2001:2::/64"})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if !reflect.DeepEqual(users, original) {
		t.Fatal("modified user routes")
	}
	if got := effectiveRoutes(options, users, false, ranges); !reflect.DeepEqual(got, users) {
		t.Fatalf("disabled auto route changed routes: %v", got)
	}
	configuration.IPv6.Store(false)
	if got := effectiveRoutes(options, users, true, ranges); len(got) != 2 {
		t.Fatalf("IPv6 route added while global IPv6 is disabled: %v", got)
	}
	configuration.IPv6.Store(true)
	options.Inet6Address = nil
	got = effectiveRoutes(options, users, true, ranges)
	if len(got) != 2 {
		t.Fatalf("IPv6 route added without IPv6 portal: %v", got)
	}
	options.Inet4Address = nil
	if got := effectiveRoutes(options, nil, true, ranges); len(got) != 0 {
		t.Fatalf("routes added without a portal: %v", got)
	}
	options.Inet4Address = []netip.Prefix{netip.MustParsePrefix("172.19.0.1/24")}
	users = toRoutes([]string{"198.18.0.0/16"})
	ranges[0] = netip.MustParsePrefix("198.19.0.0/16")
	got = effectiveRoutes(options, users, true, ranges)
	if len(got) != 2 || got[0] != users[0] {
		t.Fatalf("lost user-authored old FakeIP route: %v", got)
	}
}

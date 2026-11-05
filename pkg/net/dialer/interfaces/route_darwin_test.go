package interfaces

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestDarwinRoutesIgnoreInterfaceScope(t *testing.T) {
	ifaces := map[int]Interface{
		1: {Interface: &net.Interface{Index: 1, Name: "en0"}},
		2: {Interface: &net.Interface{Index: 2, Name: "utun4"}},
	}
	message := func(prefix string, index, flags int) route.Message {
		p := netip.MustParsePrefix(prefix)
		mask := net.CIDRMask(p.Bits(), p.Addr().BitLen())
		addrs := make([]route.Addr, unix.RTAX_NETMASK+1)
		if p.Addr().Is4() {
			addrs[unix.RTAX_DST] = &route.Inet4Addr{IP: p.Addr().As4()}
			addrs[unix.RTAX_NETMASK] = &route.Inet4Addr{IP: [4]byte(mask)}
		} else {
			addrs[unix.RTAX_DST] = &route.Inet6Addr{IP: p.Addr().As16()}
			addrs[unix.RTAX_NETMASK] = &route.Inet6Addr{IP: [16]byte(mask)}
		}
		return &route.RouteMessage{Index: index, Flags: flags, Addrs: addrs}
	}
	messages := []route.Message{
		message("0.0.0.0/0", 1, 0),
		message("::/0", 1, 0),
		message("0.0.0.0/0", 2, unix.RTF_IFSCOPE),
		message("::/0", 2, unix.RTF_IFSCOPE),
		message("192.0.2.1/32", 2, unix.RTF_IFSCOPE),
		message("2001:db8::1/128", 2, unix.RTF_IFSCOPE),
		// Actual tunnel routes remain eligible for automatic selection.
		message("198.18.0.0/16", 2, 0),
		message("2001:2::/48", 2, 0),
	}
	for _, order := range []struct {
		name    string
		reverse bool
	}{{"forward", false}, {"reverse", true}} {
		t.Run(order.name, func(t *testing.T) {
			msgs := slices.Clone(messages)
			if order.reverse {
				slices.Reverse(msgs)
			}
			rs := routesFromMessages(msgs, ifaces)
			trie := rs.ToTrie()
			for _, tc := range []struct{ ip, iface string }{
				{"203.0.113.1", "en0"},
				{"2001:db8:1::1", "en0"},
				{"192.0.2.1", "en0"},
				{"2001:db8::1", "en0"},
				{"198.18.0.1", "utun4"},
				{"2001:2::1", "utun4"},
			} {
				if got, ok := trie.Search(tc.ip); !ok || got != tc.iface {
					t.Errorf("route for %s = (%q, %v), want %q", tc.ip, got, ok, tc.iface)
				}
			}
			if len(rs.v4) != 2 || len(rs.v6) != 2 {
				t.Errorf("snapshot contains scoped routes: v4=%d, v6=%d", len(rs.v4), len(rs.v6))
			}
		})
	}
}

func TestDarwinScopedRoutesDoNotSupplyDefault(t *testing.T) {
	ifaces := map[int]Interface{
		1: {Interface: &net.Interface{Index: 1, Name: "utun4"}},
	}
	msgs := []route.Message{
		&route.RouteMessage{Index: 1, Flags: unix.RTF_IFSCOPE, Addrs: []route.Addr{
			unix.RTAX_DST:     &route.Inet6Addr{},
			unix.RTAX_NETMASK: &route.Inet6Addr{},
		}},
	}
	if _, ok := routesFromMessages(msgs, ifaces).ToTrie().Search("2001:db8::1"); ok {
		t.Fatal("a scoped-only default must leave automatic interface selection to the fallback")
	}
}

// Includes interface enumeration and FetchRIB; only parsing is cached.
func BenchmarkDarwinRoutes(b *testing.B) {
	if _, err := routes(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := routes(); err != nil {
			b.Fatal(err)
		}
	}
}

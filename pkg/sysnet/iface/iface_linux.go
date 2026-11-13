//go:build linux && !android

package iface

import (
	"net"
	"net/netip"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func platformType(ifc net.Interface) string {
	link, err := netlink.LinkByIndex(ifc.Index)
	if err != nil {
		return ""
	}
	switch link.Type() {
	case "tuntap", "wireguard", "ipip", "gre", "sit", "ip6tnl", "vti", "ppp":
		return TypeTunnel
	case "bridge":
		return TypeBridge
	case "veth", "dummy", "vlan", "macvlan", "ipvlan", "vxlan", "bond":
		return TypeVirtual
	case "device":
		if _, err := os.Stat("/sys/class/net/" + ifc.Name + "/wireless"); err == nil {
			return TypeWiFi
		}
		return TypeEthernet
	}
	return ""
}

// platformGateways reads next hops from the main table, preferring the
// default route of each interface.
func platformGateways() map[int][2]netip.Addr {
	out := map[int][2]netip.Addr{}
	for slot, f := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteListFiltered(f, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
		if err != nil {
			continue
		}
		set := func(link int, gw net.IP, def bool) {
			a, ok := netip.AddrFromSlice(gw)
			if !ok || link == 0 {
				return
			}
			entry := out[link]
			if !entry[slot].IsValid() || def {
				entry[slot] = a.Unmap()
				out[link] = entry
			}
		}
		for _, r := range routes {
			def := r.Dst == nil || r.Dst.IP.IsUnspecified() && maskBits(r.Dst) == 0
			if len(r.Gw) != 0 {
				set(r.LinkIndex, r.Gw, def)
			}
			for _, hop := range r.MultiPath {
				set(hop.LinkIndex, hop.Gw, def)
			}
		}
	}
	return out
}

func maskBits(n *net.IPNet) int {
	bits, _ := n.Mask.Size()
	return bits
}

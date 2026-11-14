//go:build linux && !android

package netlink

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var routeTypes = map[int]string{unix.RTN_UNICAST: "unicast", unix.RTN_LOCAL: "local", unix.RTN_BROADCAST: "broadcast",
	unix.RTN_BLACKHOLE: "blackhole", unix.RTN_UNREACHABLE: "unreachable", unix.RTN_PROHIBIT: "prohibit", unix.RTN_MULTICAST: "multicast"}

// ListRoutes returns the routes of every table except "local" (the kernel's
// own addresses) and the policy rules.
func ListRoutes() ([]RouteEntry, []PolicyRuleEntry, error) {
	var routes []RouteEntry
	var rules []PolicyRuleEntry
	for _, f := range []int{unix.AF_INET, unix.AF_INET6} {
		list, err := netlink.RouteListFiltered(f, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return nil, nil, err
		}
		for _, r := range list {
			if r.Table == unix.RT_TABLE_LOCAL {
				continue
			}
			e := RouteEntry{Link: r.LinkIndex, Table: r.Table, Metric: r.Priority, Protocol: int(r.Protocol), Type: routeTypes[r.Type]}
			if r.Dst != nil {
				a, _ := netip.AddrFromSlice(r.Dst.IP)
				bits, _ := r.Dst.Mask.Size()
				e.Destination = netip.PrefixFrom(a.Unmap(), bits)
			} else if f == unix.AF_INET {
				e.Destination = netip.MustParsePrefix("0.0.0.0/0")
			} else {
				e.Destination = netip.MustParsePrefix("::/0")
			}
			if gw, ok := netip.AddrFromSlice(r.Gw); ok {
				e.Gateway = gw.Unmap()
			} else if len(r.MultiPath) != 0 {
				if gw, ok := netip.AddrFromSlice(r.MultiPath[0].Gw); ok {
					e.Gateway, e.Link = gw.Unmap(), r.MultiPath[0].LinkIndex
				}
			}
			routes = append(routes, e)
		}
		list2, err := netlink.RuleList(f)
		if err != nil {
			return nil, nil, err
		}
		for _, r := range list2 {
			family := 4
			if f == unix.AF_INET6 {
				family = 6
			}
			rules = append(rules, PolicyRuleEntry{Priority: r.Priority, Family: family, Selector: ruleSelector(r), Table: r.Table, Protocol: int(r.Protocol)})
		}
	}
	return routes, rules, nil
}

func ruleSelector(r netlink.Rule) string {
	var parts []string
	if r.Src != nil {
		parts = append(parts, "from "+r.Src.String())
	}
	if r.Dst != nil {
		parts = append(parts, "to "+r.Dst.String())
	}
	if r.IifName != "" {
		parts = append(parts, "iif "+r.IifName)
	}
	if r.OifName != "" {
		parts = append(parts, "oif "+r.OifName)
	}
	if r.Mark != 0 {
		parts = append(parts, fmt.Sprintf("fwmark %#x", r.Mark))
	}
	if len(parts) == 0 {
		return "from all"
	}
	return strings.Join(parts, " ")
}

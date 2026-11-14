//go:build linux && !android

package netlink

import (
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ProtectionRule is the state of one family's TUN policy rule.
type ProtectionRule struct {
	IPv6     bool
	Priority int
	Table    int
	Selector string
	// Present: installed with the mark exclusion. Old: an unmarked rule of
	// ours that sends marked sockets into the TUN. Foreign: another program
	// uses the priority.
	Present, Old, Foreign bool
}

// ProtectionRules reads the TUN policy rules of both families.
func ProtectionRules() ([]ProtectionRule, error) {
	var out []ProtectionRule
	for _, f := range []int{unix.AF_INET, unix.AF_INET6} {
		want := policyRule(f)
		rules, err := netlink.RuleList(f)
		if err != nil {
			return nil, fmt.Errorf("list policy rules: %w", err)
		}
		r := ProtectionRule{IPv6: f == unix.AF_INET6, Priority: want.Priority, Table: want.Table,
			Selector: fmt.Sprintf("not fwmark %#x lookup %d", SocketProtectionMark, want.Table)}
		for _, existing := range rules {
			if existing.Priority != want.Priority {
				continue
			}
			switch {
			case sameRule(existing, want):
				r.Present = true
			case ownRule(existing, want):
				r.Old = true
			default:
				r.Foreign = true
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// MainRoutesVia lists main-table routes through links (Yuhaiin's TUNs). A
// protected socket matching one is rejected by the SkipMark filter instead of
// reaching the Internet.
func MainRoutesVia(links []int) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteListFiltered(f, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return nil, err
		}
		for _, r := range routes {
			for _, l := range links {
				if r.LinkIndex != l || r.Dst == nil {
					continue
				}
				// Connected subnets of the TUN itself are expected.
				if r.Scope == netlink.SCOPE_LINK && r.Protocol == unix.RTPROT_KERNEL {
					continue
				}
				ip, _ := netip.AddrFromSlice(r.Dst.IP)
				bits, _ := r.Dst.Mask.Size()
				out = append(out, netip.PrefixFrom(ip.Unmap(), bits))
			}
		}
	}
	return out, nil
}

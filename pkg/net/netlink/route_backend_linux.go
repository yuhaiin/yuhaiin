//go:build linux && !android

package netlink

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Linux system routes live in one dedicated table, consulted by one policy
// rule per family ahead of the main table. The table may hold routes to
// several interfaces: the policy engine guarantees each prefix has one target.
const (
	tunRouteTable = 63
	// routeProtocol marks routes this process installs (rtm_protocol), so a
	// restart can remove routes left by a crash without touching others.
	routeProtocol = netlink.RouteProtocol(RouteProtocolYuhaiin)
	ruleV4        = 30001
	ruleV6        = 30002
)

type linuxRouteBackend struct {
	// rules records the policy rules this backend owns, by family.
	rules map[int]bool
}

func newPlatformRouteBackend() (routeBackend, error) {
	b := &linuxRouteBackend{rules: map[int]bool{}}
	if err := b.removeStale(); err != nil {
		return nil, fmt.Errorf("remove stale system routes: %w", err)
	}
	return b, nil
}

func family(p netip.Prefix) int {
	if p.Addr().Is4() {
		return unix.AF_INET
	}
	return unix.AF_INET6
}

func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

func (b *linuxRouteBackend) route(r SystemRoute) netlink.Route {
	route := netlink.Route{Dst: ipNet(r.Prefix), LinkIndex: r.Link, Table: tunRouteTable, Protocol: routeProtocol}
	if r.Gateway.IsValid() {
		route.Gw = r.Gateway.AsSlice()
	} else {
		route.Scope = netlink.SCOPE_LINK
	}
	return route
}

// removeStale deletes routes with this process's protocol marker from the
// dedicated table, left behind when a previous run could not clean up.
func (b *linuxRouteBackend) removeStale() error {
	var result error
	for _, f := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteListFiltered(f, &netlink.Route{Table: tunRouteTable, Protocol: routeProtocol}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		for _, r := range routes {
			if err := netlink.RouteDel(&r); err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
				result = errors.Join(result, err)
			}
		}
	}
	return result
}

func (b *linuxRouteBackend) existing(r SystemRoute) ([]netlink.Route, error) {
	return netlink.RouteListFiltered(family(r.Prefix), &netlink.Route{Table: tunRouteTable, Dst: ipNet(r.Prefix)}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
}

func sameTarget(existing netlink.Route, r SystemRoute) bool {
	gw, _ := netip.AddrFromSlice(existing.Gw)
	return existing.LinkIndex == r.Link && gw.Unmap() == r.Gateway && existing.Type == unix.RTN_UNICAST
}

func (b *linuxRouteBackend) Add(r SystemRoute) (bool, error) {
	if err := b.ensureRule(family(r.Prefix)); err != nil {
		return false, err
	}
	route := b.route(r)
	err := netlink.RouteAdd(&route)
	if !errors.Is(err, unix.EEXIST) {
		return err == nil, err
	}
	existing, queryErr := b.existing(r)
	if queryErr != nil {
		return false, err
	}
	for _, e := range existing {
		if sameTarget(e, r) {
			// Ours from an earlier update or an identical route: usable.
			return e.Protocol == routeProtocol, nil
		}
	}
	return false, fmt.Errorf("%w: %w", ErrRouteConflict, err)
}

func (b *linuxRouteBackend) Replace(old, new SystemRoute) error {
	route := b.route(new)
	return netlink.RouteReplace(&route)
}

func (b *linuxRouteBackend) Delete(r SystemRoute) error {
	existing, err := b.existing(r)
	if err != nil {
		return err
	}
	for _, e := range existing {
		if e.Protocol != routeProtocol || !sameTarget(e, r) {
			continue
		}
		// Delete with the queried attributes instead of a wildcard match.
		err = netlink.RouteDel(&e)
		if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) {
			return nil
		}
		return err
	}
	// Already removed with its interface, or replaced by another owner.
	return nil
}

func (b *linuxRouteBackend) Close() error {
	var result error
	for f := range b.rules {
		if err := netlink.RuleDel(policyRule(f)); err != nil && !errors.Is(err, unix.ENOENT) {
			result = errors.Join(result, fmt.Errorf("delete policy rule: %w", err))
			continue
		}
		delete(b.rules, f)
	}
	return result
}

func policyRule(f int) *netlink.Rule {
	r := netlink.NewRule()
	r.Priority = ruleV4
	if f == unix.AF_INET6 {
		r.Priority = ruleV6
	}
	r.Table = tunRouteTable
	r.Family = f
	r.Protocol = RouteProtocolYuhaiin
	return r
}

// ensureRule installs the family's policy rule once. A matching existing rule
// (for example from a crashed run) is reused; a different rule at the same
// priority belongs to someone else and is reported instead of replaced.
func (b *linuxRouteBackend) ensureRule(f int) error {
	if b.rules[f] {
		return nil
	}
	want := policyRule(f)
	rules, err := netlink.RuleList(f)
	if err != nil {
		return fmt.Errorf("list policy rules: %w", err)
	}
	for _, existing := range rules {
		if existing.Priority != want.Priority {
			continue
		}
		existing.Protocol = want.Protocol
		if reflect.DeepEqual(existing, *want) {
			// Created by this program before (same table and priority).
			b.rules[f] = true
			return nil
		}
		return fmt.Errorf("policy rule priority %d is already used by another program", want.Priority)
	}
	if err := netlink.RuleAdd(want); err != nil {
		return fmt.Errorf("add policy rule: %w", err)
	}
	b.rules[f] = true
	return nil
}

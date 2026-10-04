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

const tunRouteTable = 63

type linuxRouteBackend struct {
	linkIndex int
	rules     map[int]bool
}

func (b *linuxRouteBackend) route(p netip.Prefix) netlink.Route {
	return netlink.Route{Dst: &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}, LinkIndex: b.linkIndex, Table: tunRouteTable}
}

func (b *linuxRouteBackend) Add(p netip.Prefix) (bool, error) {
	family := unix.AF_INET6
	if p.Addr().Is4() {
		family = unix.AF_INET
	}
	if !b.rules[family] {
		if err := acquireTunRule(family); err != nil {
			return false, err
		}
		b.rules[family] = true
	}
	r := b.route(p)
	err := netlink.RouteAdd(&r)
	if errors.Is(err, unix.EEXIST) {
		existing, queryErr := netlink.RouteListFiltered(family, &r, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST|netlink.RT_FILTER_OIF)
		if queryErr == nil {
			for _, route := range existing {
				if len(route.Gw) == 0 && route.Priority == 0 && route.Type == unix.RTN_UNICAST {
					return false, nil
				}
			}
		}
	}
	return err == nil, err
}

func (b *linuxRouteBackend) Delete(p netip.Prefix) error {
	r := b.route(p)
	family := unix.AF_INET6
	if p.Addr().Is4() {
		family = unix.AF_INET
	}
	existing, err := netlink.RouteListFiltered(family, &r, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST|netlink.RT_FILTER_OIF)
	if err != nil {
		return err
	}
	for _, route := range existing {
		if len(route.Gw) != 0 || route.Priority != 0 || route.Type != unix.RTN_UNICAST {
			continue
		}
		// Use the queried route's full attributes instead of a wildcard deletion.
		err = netlink.RouteDel(&route)
		if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) {
			return nil
		}
		return err
	}
	// The interface or route was already removed, or replaced by another owner.
	return nil
}

func (b *linuxRouteBackend) Close(routesPending bool) error {
	if routesPending {
		return nil
	}
	var result error
	for family := range b.rules {
		if err := releaseTunRule(family); err != nil {
			result = errors.Join(result, err)
		} else {
			delete(b.rules, family)
		}
	}
	return result
}

// Linux TUNs share table 63 and its policy rules. Reference counting prevents
// closing one TUN from removing a rule still needed by another TUN.
var tunRules sharedRouteRules

func tunRule(family int) *netlink.Rule {
	r := netlink.NewRule()
	r.Priority = 30001
	if family == unix.AF_INET6 {
		r.Priority = 30002
	}
	r.Table = tunRouteTable
	r.Family = family
	return r
}

func acquireTunRule(family int) error {
	return tunRules.acquire(family, func() (bool, error) {
		r := tunRule(family)
		rules, err := netlink.RuleList(family)
		if err != nil {
			return false, fmt.Errorf("list TUN policy rules: %w", err)
		}
		for _, existing := range rules {
			if existing.Priority != r.Priority {
				continue
			}
			// Ignore kernel-populated protocol metadata when comparing selectors.
			existing.Protocol = r.Protocol
			if reflect.DeepEqual(existing, *r) {
				return false, nil
			}
			return false, fmt.Errorf("TUN policy rule priority %d is already in use", r.Priority)
		}
		if err := netlink.RuleAdd(r); err != nil {
			return false, fmt.Errorf("add TUN policy rule: %w", err)
		}
		return true, nil
	})
}

func releaseTunRule(family int) error {
	return tunRules.release(family, func() error {
		if err := netlink.RuleDel(tunRule(family)); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("delete TUN policy rule: %w", err)
		}
		return nil
	})
}

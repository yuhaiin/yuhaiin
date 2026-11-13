package netlink

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// darwinRouteBackend installs routes in the single macOS routing table. There
// is no policy routing: the policy engine has already made every prefix
// unique, and the kernel's longest-prefix match picks between prefixes.
type darwinRouteBackend struct{}

func newPlatformRouteBackend() (routeBackend, error) { return darwinRouteBackend{}, nil }

// gateway returns the next hop written to the routing socket. Point-to-point
// interfaces such as utun use their own address, like `route add -interface`.
func gateway(r SystemRoute) (netip.Addr, error) {
	if r.Gateway.IsValid() {
		return r.Gateway, nil
	}
	iface, err := net.InterfaceByIndex(r.Link)
	if err != nil {
		return netip.Addr{}, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap().Is4() == r.Prefix.Addr().Is4() && !ip.IsLinkLocalUnicast() {
				return ip.Unmap(), nil
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("interface %s has no %s address to route through", iface.Name, familyName(r.Prefix))
}

func familyName(p netip.Prefix) string {
	if p.Addr().Is4() {
		return "IPv4"
	}
	return "IPv6"
}

func (darwinRouteBackend) Add(r SystemRoute) (bool, error) {
	gw, err := gateway(r)
	if err != nil {
		return false, err
	}
	err = writeRoute(r.Prefix, gw, unix.RTM_ADD, r.Link)
	if errors.Is(err, unix.EEXIST) {
		index, existing, found, queryErr := lookupDarwinRoute(r.Prefix)
		if queryErr == nil && found {
			return darwinExistingRoute(r.Link, gw, index, existing, err)
		}
	}
	return err == nil, err
}

// darwinExistingRoute decides how an RTM_ADD that failed with EEXIST is
// handled: a matching route on the same interface is borrowed (never
// deleted), and a route of another interface is reported as a conflict.
func darwinExistingRoute(link int, gw netip.Addr, index int, gateway netip.Addr, addErr error) (bool, error) {
	if index == link && (!gateway.IsValid() || gateway == gw) {
		return false, nil
	}
	return false, fmt.Errorf("%w (interface index %d): %w", ErrRouteConflict, index, addErr)
}

func (darwinRouteBackend) Delete(r SystemRoute) error {
	index, existing, found, err := lookupDarwinRoute(r.Prefix)
	if err != nil {
		return err
	}
	if !found || index != r.Link {
		// Gone with its interface, or replaced: no longer ours to remove.
		return nil
	}
	gw, err := gateway(r)
	if err != nil {
		// The interface lost its address; the route went with it.
		gw = existing
	}
	if existing.IsValid() && gw != existing {
		return nil
	}
	err = writeRoute(r.Prefix, gw, unix.RTM_DELETE, r.Link)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

func (darwinRouteBackend) Close() error { return nil }

func darwinIP(a route.Addr) netip.Addr {
	switch a := a.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(a.IP)
	case *route.Inet6Addr:
		return netip.AddrFrom16(a.IP)
	}
	return netip.Addr{}
}

func lookupDarwinRoute(p netip.Prefix) (int, netip.Addr, bool, error) {
	family := unix.AF_INET6
	if p.Addr().Is4() {
		family = unix.AF_INET
	}
	rib, err := route.FetchRIB(family, route.RIBTypeRoute, 0)
	if err != nil {
		return 0, netip.Addr{}, false, err
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return 0, netip.Addr{}, false, err
	}
	for _, message := range messages {
		r, ok := message.(*route.RouteMessage)
		if !ok || len(r.Addrs) <= syscall.RTAX_NETMASK {
			continue
		}
		destination := darwinIP(r.Addrs[syscall.RTAX_DST])
		if destination != p.Addr() {
			continue
		}
		mask := darwinIP(r.Addrs[syscall.RTAX_NETMASK])
		bits := 0
		if mask.IsValid() {
			bits, _ = net.IPMask(mask.AsSlice()).Size()
		}
		if bits != p.Bits() {
			continue
		}
		return r.Index, darwinIP(r.Addrs[syscall.RTAX_GATEWAY]), true, nil
	}
	return 0, netip.Addr{}, false, nil
}

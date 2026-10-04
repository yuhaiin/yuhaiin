package netlink

import (
	"errors"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

type darwinRouteBackend struct {
	index      int
	v4, v6     netip.Addr
	restoreDNS func()
}

func (b *darwinRouteBackend) gateway(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		return b.v4
	}
	return b.v6
}

func (b *darwinRouteBackend) Add(p netip.Prefix) (bool, error) {
	err := writeRoute(p, b.gateway(p), unix.RTM_ADD, b.index)
	if errors.Is(err, unix.EEXIST) {
		index, gateway, found, queryErr := lookupDarwinRoute(p)
		if queryErr == nil && found && index == b.index && (!gateway.IsValid() || gateway == b.gateway(p)) {
			return false, nil
		}
	}
	return err == nil, err
}

func (b *darwinRouteBackend) Delete(p netip.Prefix) error {
	index, gateway, found, err := lookupDarwinRoute(p)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if index != b.index || gateway != b.gateway(p) {
		// An external replacement is no longer ours to remove.
		return nil
	}
	err = writeRoute(p, b.gateway(p), unix.RTM_DELETE, b.index)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

func (b *darwinRouteBackend) Close(_ bool) error {
	if b.restoreDNS != nil {
		b.restoreDNS()
		b.restoreDNS = nil
	}
	return nil
}

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

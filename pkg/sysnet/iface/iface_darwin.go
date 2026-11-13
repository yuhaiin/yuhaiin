package iface

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func platformType(net.Interface) string { return "" }

func darwinAddr(a route.Addr) netip.Addr {
	switch a := a.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(a.IP)
	case *route.Inet6Addr:
		return netip.AddrFrom16(a.IP)
	}
	return netip.Addr{}
}

// platformGateways reads gateways of default routes from the routing table.
func platformGateways() map[int][2]netip.Addr {
	out := map[int][2]netip.Addr{}
	for slot, f := range []int{unix.AF_INET, unix.AF_INET6} {
		rib, err := route.FetchRIB(f, route.RIBTypeRoute, 0)
		if err != nil {
			continue
		}
		messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
		if err != nil {
			continue
		}
		for _, m := range messages {
			r, ok := m.(*route.RouteMessage)
			if !ok || r.Flags&unix.RTF_GATEWAY == 0 || r.Flags&unix.RTF_IFSCOPE != 0 || len(r.Addrs) <= syscall.RTAX_GATEWAY {
				continue
			}
			dst := darwinAddr(r.Addrs[syscall.RTAX_DST])
			if !dst.IsValid() || !dst.IsUnspecified() {
				continue
			}
			gw := darwinAddr(r.Addrs[syscall.RTAX_GATEWAY])
			if !gw.IsValid() {
				continue
			}
			entry := out[r.Index]
			if !entry[slot].IsValid() {
				entry[slot] = gw
				out[r.Index] = entry
			}
		}
	}
	return out
}

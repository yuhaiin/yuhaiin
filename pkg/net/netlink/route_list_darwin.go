package netlink

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// ListRoutes returns the routes of the macOS routing table. There are no
// policy rules.
func ListRoutes() ([]RouteEntry, []PolicyRuleEntry, error) {
	var out []RouteEntry
	for _, f := range []int{unix.AF_INET, unix.AF_INET6} {
		rib, err := route.FetchRIB(f, route.RIBTypeRoute, 0)
		if err != nil {
			return nil, nil, err
		}
		messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
		if err != nil {
			return nil, nil, err
		}
		for _, m := range messages {
			r, ok := m.(*route.RouteMessage)
			if !ok || len(r.Addrs) <= syscall.RTAX_DST {
				continue
			}
			dst := darwinIP(r.Addrs[syscall.RTAX_DST])
			if !dst.IsValid() {
				continue
			}
			bits := dst.BitLen()
			if r.Flags&unix.RTF_HOST == 0 {
				bits = 0
				if len(r.Addrs) > syscall.RTAX_NETMASK {
					if mask := darwinIP(r.Addrs[syscall.RTAX_NETMASK]); mask.IsValid() {
						bits, _ = net.IPMask(mask.AsSlice()).Size()
					}
				}
			}
			e := RouteEntry{Destination: netip.PrefixFrom(dst, bits).Masked(), Link: r.Index, Type: "unicast", Cloned: r.Flags&unix.RTF_WASCLONED != 0}
			if r.Flags&unix.RTF_GATEWAY != 0 && len(r.Addrs) > syscall.RTAX_GATEWAY {
				e.Gateway = darwinIP(r.Addrs[syscall.RTAX_GATEWAY])
			}
			if r.Flags&unix.RTF_BLACKHOLE != 0 {
				e.Type = "blackhole"
			} else if r.Flags&unix.RTF_LOCAL != 0 {
				e.Type = "local"
			}
			out = append(out, e)
		}
	}
	return out, nil, nil
}

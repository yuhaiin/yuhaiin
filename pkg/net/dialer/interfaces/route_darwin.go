package interfaces

import (
	"bytes"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// parsedRIB retains the last macOS route snapshot. Network notifications can
// arrive frequently with no actual RIB changes; skip the expensive ParseRIB
// and route conversion in that case. Interface names are part of the key.
//
// The same dump also yields the default route, so one refresh fetches and
// parses the RIB once instead of once for routes and again for the default.
var parsedRIB struct {
	sync.Mutex
	raw          []byte
	names        map[int]string
	routes       router
	defaultIndex int // before utun delegation, which can change independently
	defaultErr   error
	fetchedAt    time.Time
}

// recentRIB bounds how long DefaultRouteInterfaceIndex reuses the dump that
// routesFrom just took in the same refresh.
const recentRIB = time.Second

func sameRouteInterfaceNames(names map[int]string, ifaces map[int]Interface) bool {
	if len(names) != len(ifaces) {
		return false
	}
	for index, iface := range ifaces {
		if names[index] != iface.Name {
			return false
		}
	}
	return true
}

func routesFrom(ifaces map[int]Interface) (router, error) {
	messages, err := route.FetchRIB(unix.AF_UNSPEC, unix.NET_RT_DUMP, 0)
	if err != nil {
		return router{}, err
	}

	parsedRIB.Lock()
	defer parsedRIB.Unlock()
	if parsedRIB.raw != nil && bytes.Equal(parsedRIB.raw, messages) && sameRouteInterfaceNames(parsedRIB.names, ifaces) {
		parsedRIB.fetchedAt = time.Now()
		return parsedRIB.routes, nil
	}

	msgs, err := route.ParseRIB(unix.NET_RT_DUMP, messages)
	if err != nil {
		return router{}, err
	}

	ret := routesFromMessages(msgs, ifaces)

	// Route snapshots are immutable after publication.
	parsedRIB.raw = messages
	parsedRIB.names = make(map[int]string, len(ifaces))
	for index, iface := range ifaces {
		parsedRIB.names[index] = iface.Name
	}
	parsedRIB.routes = ret
	parsedRIB.defaultIndex, parsedRIB.defaultErr = defaultRouteIndexFromMessages(msgs)
	parsedRIB.fetchedAt = time.Now()
	return ret, nil
}

// recentDefaultRouteIndex returns the default route of a dump taken within
// recentRIB, before delegation is resolved.
func recentDefaultRouteIndex() (index int, ok bool, err error) {
	parsedRIB.Lock()
	defer parsedRIB.Unlock()
	if parsedRIB.raw == nil || time.Since(parsedRIB.fetchedAt) > recentRIB {
		return 0, false, nil
	}
	return parsedRIB.defaultIndex, true, parsedRIB.defaultErr
}

// churnRoute reports routing-table entries the kernel creates and expires on
// its own as traffic flows: ARP/NDP neighbor entries and host routes cloned
// from a parent route. Both resolve to their parent's interface, so neither
// changes automatic interface selection, but they change the dump constantly.
func churnRoute(flags int) bool {
	return flags&(unix.RTF_LLINFO|unix.RTF_WASCLONED) != 0
}

// routesFromMessages builds the unscoped routing table used for automatic
// outbound interface selection.
func routesFromMessages(msgs []route.Message, ifaces map[int]Interface) router {
	ret := router{}

	for _, m := range msgs {
		switch msg := m.(type) {
		case *route.RouteMessage:
			// Interface-scoped routes only apply after the caller chooses that
			// interface. Flattening them into this trie can replace the global
			// default with an unrelated tunnel, especially for IPv6.
			if msg.Flags&unix.RTF_IFSCOPE != 0 || churnRoute(msg.Flags) {
				continue
			}
			if len(msg.Addrs) < 3 {
				continue
			}

			iface, ok := ifaces[msg.Index]
			if !ok {
				continue
			}

			dst := msg.Addrs[0]
			mask := msg.Addrs[2]

			var ip netip.Addr
			switch dst := dst.(type) {
			case *route.Inet4Addr:
				ip = netip.AddrFrom4(dst.IP)
			case *route.Inet6Addr:
				ip = netip.AddrFrom16(dst.IP)
			default:
				continue
			}

			var bits = ip.BitLen()
			switch mask := mask.(type) {
			case *route.Inet4Addr:
				bits, _ = net.IPMask(mask.IP[:]).Size()
			case *route.Inet6Addr:
				bits, _ = net.IPMask(mask.IP[:]).Size()
			}

			// gateway := msg.Addrs[1]
			// var gatewayAddr netip.Addr
			// switch g := gateway.(type) {
			// case *route.Inet4Addr:
			// 	gatewayAddr = netip.AddrFrom4(g.IP)
			// case *route.Inet6Addr:
			// 	gatewayAddr = netip.AddrFrom16(g.IP)
			// }

			var gateway netip.Addr
			switch g := msg.Addrs[1].(type) {
			case *route.Inet4Addr:
				gateway = netip.AddrFrom4(g.IP)
			case *route.Inet6Addr:
				gateway = netip.AddrFrom16(g.IP)
			}
			prefix := netip.PrefixFrom(ip, bits)

			if ip.Is4() {
				ret.v4 = append(ret.v4, rtInfo{Dst: prefix, OutputIface: iface.Name, Gateway: gateway})
			} else {
				ret.v6 = append(ret.v6, rtInfo{Dst: prefix, OutputIface: iface.Name, Gateway: gateway})
			}
		}
	}

	return ret
}

package interfaces

import (
	"net"
	"net/netip"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func routes() (router, error) {
	ifaces, err := interfacesMap()
	if err != nil {
		return router{}, err
	}

	messages, err := route.FetchRIB(unix.AF_UNSPEC, unix.NET_RT_DUMP, 0)
	if err != nil {
		return router{}, err
	}

	msgs, err := route.ParseRIB(unix.NET_RT_DUMP, messages)
	if err != nil {
		return router{}, err
	}

	ret := router{}

	for _, m := range msgs {
		switch msg := m.(type) {
		case *route.RouteMessage:
			if len(msg.Addrs) < 3 {
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

			prefix := netip.PrefixFrom(ip, bits)

			if ip.Is4() {
				ret.v4 = append(ret.v4, rtInfo{
					Dst:         prefix,
					OutputIface: ifaces[msg.Index].Name,
				})
			} else {
				ret.v6 = append(ret.v6, rtInfo{
					Dst:         prefix,
					OutputIface: ifaces[msg.Index].Name,
				})
			}
		}
	}

	return ret, nil
}

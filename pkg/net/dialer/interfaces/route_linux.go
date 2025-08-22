//go:build linux && !android

package interfaces

import (
	"net/netip"
	"syscall"
	"unsafe"
)

func routes() (router, error) {
	ifaces, err := interfacesMap()
	if err != nil {
		return router{}, err
	}

	rtr := router{}
	tab, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_UNSPEC)
	if err != nil {
		return router{}, err
	}
	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return router{}, err
	}
loop:
	for _, m := range msgs {
		switch m.Header.Type {
		case syscall.NLMSG_DONE:
			break loop
		case syscall.RTM_NEWROUTE:
			rt := (*syscall.RtMsg)(unsafe.Pointer(&m.Data[0]))
			routeInfo := rtInfo{}
			attrs, err := syscall.ParseNetlinkRouteAttr(&m)
			if err != nil {
				return router{}, err
			}
			if rt.Family != syscall.AF_INET && rt.Family != syscall.AF_INET6 {
				continue loop
			}
			for _, attr := range attrs {
				switch attr.Attr.Type {
				case syscall.RTA_DST:
					ip, ok := netip.AddrFromSlice(attr.Value)
					if !ok {
						continue
					}

					routeInfo.Dst = netip.PrefixFrom(ip, int(rt.Dst_len))

					// routeInfo.Dst = &net.IPNet{
					// 	IP:   net.IP(attr.Value),
					// 	Mask: net.CIDRMask(int(rt.Dst_len), len(attr.Value)*8),
					// }
				case syscall.RTA_SRC:
					// routeInfo.Src = &net.IPNet{
					// 	IP:   net.IP(attr.Value),
					// 	Mask: net.CIDRMask(int(rt.Src_len), len(attr.Value)*8),
					// }
				case syscall.RTA_GATEWAY:
					// routeInfo.Gateway = net.IP(attr.Value)
				case syscall.RTA_PREFSRC:
					// routeInfo.PrefSrc = net.IP(attr.Value)
				case syscall.RTA_IIF:
					// input := *(*uint32)(unsafe.Pointer(&attr.Value[0]))
					// if iface, ok := ifces[int(input)]; ok {
					// 	routeInfo.InputIface = iface.Name
					// }
				case syscall.RTA_OIF:
					output := *(*uint32)(unsafe.Pointer(&attr.Value[0]))
					if iface, ok := ifaces[int(output)]; ok {
						routeInfo.OutputIface = iface.Name
					}
				case syscall.RTA_PRIORITY:
					// routeInfo.Priority = *(*uint32)(unsafe.Pointer(&attr.Value[0]))
				}
			}
			if !routeInfo.Dst.IsValid() {
				continue loop
			}

			switch rt.Family {
			case syscall.AF_INET:
				rtr.v4 = append(rtr.v4, routeInfo)
			case syscall.AF_INET6:
				rtr.v6 = append(rtr.v6, routeInfo)
			default:
				// should not happen.
				continue loop
			}
		}
	}
	return rtr, nil
}

package interfaces

import (
	"errors"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// routesFrom reads both families of the forwarding table. Windows picks the
// longest prefix, then the lowest route metric plus interface metric, so each
// route carries that sum for SelectRoute.
func routesFrom(ifaces map[int]Interface) (router, error) {
	ret := router{}
	var result error
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		routes, err := winipcfg.GetIPForwardTable2(family)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		interfaceMetric := map[winipcfg.LUID]uint32{}
		for _, route := range routes {
			iface, ok := ifaces[int(route.InterfaceIndex)]
			if !ok {
				continue
			}
			metric, ok := interfaceMetric[route.InterfaceLUID]
			if !ok {
				if row, err := route.InterfaceLUID.IPInterface(family); err == nil {
					if !row.Connected {
						interfaceMetric[route.InterfaceLUID] = disconnected
						continue
					}
					metric = row.Metric
				}
				interfaceMetric[route.InterfaceLUID] = metric
			}
			if metric == disconnected {
				continue
			}
			prefix := route.DestinationPrefix.Prefix()
			info := rtInfo{Dst: prefix, OutputIface: iface.Name, Gateway: route.NextHop.Addr(), Metric: route.Metric + metric}
			if prefix.Addr().Is4() {
				ret.v4 = append(ret.v4, info)
			} else {
				ret.v6 = append(ret.v6, info)
			}
		}
	}
	if len(ret.v4) == 0 && len(ret.v6) == 0 && result != nil {
		return router{}, result
	}
	return ret, nil
}

// disconnected marks an interface whose routes cannot carry traffic now.
const disconnected = ^uint32(0)

package interfaces

import (
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func routes() (router, error) {
	ifaces, err := interfacesMap()
	if err != nil {
		return router{}, err
	}

	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return router{}, err
	}

	ret := router{}
	for _, route := range routes {
		prefix := route.DestinationPrefix.Prefix()

		if prefix.Addr().Is4() {
			ret.v4 = append(ret.v4, rtInfo{
				Dst:         prefix,
				OutputIface: ifaces[int(route.InterfaceIndex)].Name,
			})
		} else {
			ret.v6 = append(ret.v6, rtInfo{
				Dst:         prefix,
				OutputIface: ifaces[int(route.InterfaceIndex)].Name,
			})
		}
	}

	return ret, nil
}

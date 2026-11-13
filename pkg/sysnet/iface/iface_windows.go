package iface

import (
	"net"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func platformType(ifc net.Interface) string {
	luid, err := winipcfg.LUIDFromIndex(uint32(ifc.Index))
	if err != nil {
		return ""
	}
	row, err := luid.Interface()
	if err != nil {
		return ""
	}
	switch row.Type {
	case winipcfg.IfTypeEthernetCSMACD:
		return TypeEthernet
	case winipcfg.IfTypeIEEE80211:
		return TypeWiFi
	case winipcfg.IfTypePropVirtual, winipcfg.IfTypeTunnel, winipcfg.IfTypePPP:
		return TypeTunnel
	case winipcfg.IfTypeSoftwareLoopback:
		return TypeLoopback
	}
	return ""
}

// platformGateways reads next hops of default routes.
func platformGateways() map[int][2]netip.Addr {
	out := map[int][2]netip.Addr{}
	for slot, f := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		rows, err := winipcfg.GetIPForwardTable2(f)
		if err != nil {
			continue
		}
		for _, r := range rows {
			if r.DestinationPrefix.PrefixLength != 0 {
				continue
			}
			gw := r.NextHop.Addr()
			if !gw.IsValid() || gw.IsUnspecified() {
				continue
			}
			entry := out[int(r.InterfaceIndex)]
			if !entry[slot].IsValid() {
				entry[slot] = gw.Unmap()
				out[int(r.InterfaceIndex)] = entry
			}
		}
	}
	return out
}

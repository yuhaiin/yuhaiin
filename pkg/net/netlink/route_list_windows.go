package netlink

import (
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// ListRoutes returns the routes of the Windows routing table. There are no
// policy rules.
func ListRoutes() ([]RouteEntry, []PolicyRuleEntry, error) {
	var out []RouteEntry
	for _, f := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		rows, err := winipcfg.GetIPForwardTable2(f)
		if err != nil {
			return nil, nil, err
		}
		for _, r := range rows {
			e := RouteEntry{Destination: r.DestinationPrefix.Prefix(), Link: int(r.InterfaceIndex), Metric: int(r.Metric), Type: "unicast"}
			if gw := r.NextHop.Addr(); gw.IsValid() && !gw.IsUnspecified() {
				e.Gateway = gw.Unmap()
			}
			out = append(out, e)
		}
	}
	return out, nil, nil
}

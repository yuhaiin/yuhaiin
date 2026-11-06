package interfaces

import (
	"net/netip"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func stableInterfaceID(iface Interface) (string, error) {
	luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
	if err != nil {
		return "", err
	}
	return "luid:" + strconv.FormatUint(uint64(luid), 10), nil
}

func completeInterfaceNetwork(n *netstate.Network) error {
	luid, err := winipcfg.LUIDFromIndex(uint32(n.Index))
	if err != nil {
		return err
	}
	var checked [2]bool
	var connected [2]bool
	usable := make([]netip.Addr, 0, len(n.Addresses))
	for _, ip := range n.Addresses {
		index, family := 0, winipcfg.AddressFamily(windows.AF_INET)
		if ip.Is6() {
			index, family = 1, windows.AF_INET6
		}
		if !checked[index] {
			row, err := luid.IPInterface(family)
			if err != nil {
				return err
			}
			checked[index], connected[index] = true, row.Connected
		}
		if !connected[index] {
			continue
		}
		row, err := luid.IPAddress(ip)
		if err != nil {
			return err
		}
		if row.DadState == winipcfg.DadStatePreferred || row.DadState == winipcfg.DadStateDeprecated {
			usable = append(usable, ip)
		}
	}
	n.Addresses = usable
	return nil
}

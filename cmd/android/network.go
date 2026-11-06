package yuhaiin

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	di "github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
)

// UnderlyingNetwork is populated from ConnectivityManager's non-VPN Network,
// NetworkCapabilities and LinkProperties. Validated is diagnostic only: loss
// of validation, DNS settings or VPN route churn cannot retire a socket.
// Addresses contains whitespace-separated local IP addresses, without masks.
type UnderlyingNetwork struct {
	Handle         int64
	InterfaceIndex int32
	InterfaceName  string
	Addresses      string
	Available      bool
	Validated      bool
	Vpn            bool
}

type UnderlyingNetworkIter interface {
	HasNext() bool
	Next() *UnderlyingNetwork
}

// ReportUnderlyingNetworks publishes one complete, successful platform view.
// The selected handle must describe the VpnService's actual selected underlay,
// not ConnectivityManager.activeNetwork when that is yuhaiin's own VPN.
// A nil iterator or malformed/incomplete observation retains the previous view.
func ReportUnderlyingNetworks(networks UnderlyingNetworkIter, selectedHandle int64) error {
	s, err := underlyingNetworkSnapshot(networks, selectedHandle)
	if err != nil {
		return err
	}
	di.PublishUnderlyingNetworks(s)
	return nil
}

func underlyingNetworkSnapshot(networks UnderlyingNetworkIter, selectedHandle int64) (netstate.Snapshot, error) {
	if networks == nil {
		return netstate.Snapshot{}, errors.New("underlying network snapshot is unavailable")
	}
	s := netstate.Snapshot{Source: netstate.PlatformCallback}
	seen := make(map[int64]bool)
	for networks.HasNext() {
		raw := networks.Next()
		if raw == nil || raw.Handle == 0 || raw.Vpn || raw.InterfaceName == "" || seen[raw.Handle] {
			return netstate.Snapshot{}, errors.New("invalid or incomplete underlying Network identity")
		}
		seen[raw.Handle] = true
		n := netstate.Network{ID: "android:" + strconv.FormatInt(raw.Handle, 10), Index: int(raw.InterfaceIndex), Name: raw.InterfaceName, Available: raw.Available}
		for address := range strings.FieldsSeq(raw.Addresses) {
			ip, err := netip.ParseAddr(address)
			if err != nil {
				return netstate.Snapshot{}, fmt.Errorf("invalid underlying local address: %w", err)
			}
			n.Addresses = append(n.Addresses, ip.WithZone("").Unmap())
		}
		if raw.Handle == selectedHandle {
			s.Selected = n.ID
		}
		s.Networks = append(s.Networks, n)
	}
	return s, nil
}

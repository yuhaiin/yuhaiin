package interfaces

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
)

var externalNetworkState atomic.Bool

// PublishUnderlyingNetworks is the native integration boundary for an OS with
// authoritative Network identities, notably Android ConnectivityManager.
// Callers supply all relevant non-VPN networks, including temporarily offline
// networks. Unknown or failed observations must not be published as empty.
func PublishUnderlyingNetworks(s netstate.Snapshot) {
	externalNetworkState.Store(true)
	s.Source = netstate.PlatformCallback
	logLifecycleEvent(netstate.Default.Apply(s, false), "platform callback")
}

func logLifecycleEvent(e netstate.Event, reason string) {
	if e.Changes&(netstate.NetworkChanged|netstate.ConnectivityChanged) != 0 {
		log.Info("confirmed network lifecycle transition", "generation", e.Generation, "changes", e.Changes, "source", e.Source, "interface_index", e.InterfaceIndex, "reason", reason)
	}
}

func readNetworkSnapshot() (netstate.Snapshot, error) {
	ifs, err := GetInterfaceList()
	if err != nil {
		return netstate.Snapshot{}, err
	}
	return networkSnapshotFrom(ifs)
}

func networkSnapshotFrom(ifs []Interface) (netstate.Snapshot, error) {
	s := netstate.Snapshot{Source: netstate.SystemInterfaces}
	for _, iface := range ifs {
		id, err := stableInterfaceID(iface)
		if err != nil {
			return netstate.Snapshot{}, err
		}
		if id == "" {
			return netstate.Snapshot{}, fmt.Errorf("interface %q identity is unavailable", iface.Name)
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return netstate.Snapshot{}, fmt.Errorf("read interface %d addresses: %w", iface.Index, err)
		}
		available := iface.IsUp()
		if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
			available = available && iface.Flags&net.FlagRunning != 0
		}
		n := netstate.Network{ID: id, Index: iface.Index, Name: iface.Name, Available: available}
		for _, raw := range addresses {
			var ip netip.Addr
			switch a := raw.(type) {
			case *net.IPNet:
				ip, _ = netip.AddrFromSlice(a.IP)
			case *net.IPAddr:
				ip, _ = netip.AddrFromSlice(a.IP)
			}
			if ip.IsValid() && !ip.IsUnspecified() {
				n.Addresses = append(n.Addresses, ip.Unmap())
			}
		}
		if err := completeInterfaceNetwork(&n); err != nil {
			return netstate.Snapshot{}, err
		}
		s.Networks = append(s.Networks, n)
	}
	return s, nil
}

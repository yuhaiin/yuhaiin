// Package netstate tracks confirmed network identity and resource affinity.
// Route metadata is deliberately absent from network identity: refreshing a
// route cache is never, by itself, evidence that a socket is unusable.
package netstate

import (
	"net/netip"
	"slices"
)

type Generation uint64

type Change uint8

const (
	RouteChanged Change = 1 << iota
	NetworkChanged
	ConnectivityChanged
)

type Source uint8

const (
	SystemInterfaces Source = iota
	PlatformCallback
)

// Network describes one interface lifetime in the monitor's network namespace.
// ID is an OS identity (ifindex, Windows LUID, or Android Network handle), never
// a friendly name, gateway, route hash, or DNS server configuration.
type Network struct {
	ID        string
	Index     int
	Name      string // diagnostic and binding lookup only; renaming is harmless
	Available bool
	Addresses []netip.Addr
}

// Snapshot is a complete, successful observation. Providers must return an
// error instead of an incomplete list when interface/address discovery fails.
// Selected is used only with an authoritative underlying-network callback.
// A default route alone must not populate it.
type Snapshot struct {
	Networks []Network
	Selected string
	Source   Source
}

type Event struct {
	Changes        Change
	Generation     Generation
	Source         Source
	InterfaceIndex int // authoritative single-interface notifications only
}

type networkView struct {
	Network
	epoch     uint64
	addresses map[netip.Addr]uint64
	v4, v6    uint64
	anyFamily uint64
}

type view struct {
	networks     map[string]networkView
	selected     string
	lastSelected string
	generation   Generation
}

func (v *view) matches(s Snapshot) bool {
	if v.selected != s.Selected || len(v.networks) != len(s.Networks) {
		return false
	}
	for _, raw := range s.Networks {
		n, ok := v.networks[raw.ID]
		if !ok || n.Index != raw.Index || n.Name != raw.Name || n.Available != raw.Available || len(n.addresses) != len(raw.Addresses) {
			return false
		}
		for _, ip := range raw.Addresses {
			if _, ok := n.addresses[ip.Unmap()]; !ok {
				return false
			}
		}
	}
	return true
}

// Path is an immutable creation token, scoped to one network lifetime and,
// where known, its actual source address or usable address family. Its epoch
// is not compared to a global generation. Unknown paths are never invalidated.
type Path struct {
	network string
	epoch   uint64
	local   netip.Addr
	address uint64
	family  uint8
	token   uint64
}

func (p Path) Known() bool { return p.network != "" && p.epoch != 0 }

func (v *view) valid(p Path) bool {
	if !p.Known() {
		return true
	}
	n, ok := v.networks[p.network]
	if !ok || !n.Available || n.epoch != p.epoch {
		return false
	}
	if p.local.IsValid() {
		return n.addresses[p.local] == p.address && p.address != 0
	}
	switch p.family {
	case 4:
		return n.v4 == p.token
	case 6:
		return n.v6 == p.token
	default:
		return n.anyFamily == p.token
	}
}

func sameAddresses(a, b map[netip.Addr]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for ip := range a {
		if _, ok := b[ip]; !ok {
			return false
		}
	}
	return true
}

// commonAddress proves that at least one previously usable source remains.
// For wildcard UDP sockets, partial address churn cannot prove which source
// was used. Only replacement of the entire relevant family invalidates them.
func commonAddress(a, b map[netip.Addr]uint64, family uint8) bool {
	for ip := range a {
		if family == 4 && !ip.Is4() || family == 6 && !ip.Is6() {
			continue
		}
		if _, ok := b[ip]; ok {
			return true
		}
	}
	return false
}

func cloneNetwork(n Network) Network {
	n.Addresses = slices.Clone(n.Addresses)
	return n
}

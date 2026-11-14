package netlink

import (
	"net/netip"
	"slices"
	"sort"
)

// Interface-scoped default routes (macOS).
//
// A socket bound with IP_BOUND_IF / IPV6_BOUND_IF only uses routes scoped to
// its interface, or, on the primary interface, the global default. macOS
// (configd) normally installs a scoped default for every interface with a
// router. A VPN that takes over the default route can leave an interface with
// neither, and bound sockets then fail with ENETUNREACH. The planner below
// keeps a scoped default for every interface whose gateway is known,
// borrowing existing routes and creating one only when none exists.

// ScopedState of one interface and family.
const (
	ScopedPrimary     = "primary"     // the global default is on this interface
	ScopedBorrowed    = "borrowed"    // a scoped default another owner installed
	ScopedOwned       = "owned"       // a scoped default Yuhaiin installed
	ScopedUnavailable = "unavailable" // no gateway known; bound sockets may fail
	ScopedFailed      = "failed"      // creating the route failed
)

// RIBRoute is one parsed routing table entry.
type RIBRoute struct {
	Dst     netip.Prefix
	Gateway netip.Addr // invalid for interface (link) routes
	Index   int
	Scoped  bool // RTF_IFSCOPE
}

// ScopedInterface is an interface the planner considers.
type ScopedInterface struct {
	Name     string
	Index    int
	Up       bool
	Loopback bool
	OwnTun   bool
	Prefixes []netip.Prefix // configured addresses with their masks
}

// ScopedRoute is the planned scoped default of one interface and family.
type ScopedRoute struct {
	Interface string
	Index     int
	IPv6      bool
	Gateway   netip.Addr
	// Link is set for a borrowed scoped default through the interface itself.
	Link   bool
	State  string
	Reason string
}

type scopedKey struct {
	index int
	v6    bool
}

// rememberedGateway is the last router seen for an interface, with the
// addresses it had then: it stays valid while those addresses do.
type rememberedGateway struct {
	gateway  netip.Addr
	prefixes []netip.Prefix
}

// ownedScoped is a scoped default Yuhaiin installed, with the interface
// addresses it was installed for.
type ownedScoped struct {
	gateway  netip.Addr
	prefixes []netip.Prefix
}

type scopedPlanner struct {
	remembered map[scopedKey]rememberedGateway
}

func newScopedPlanner() *scopedPlanner {
	return &scopedPlanner{remembered: map[scopedKey]rememberedGateway{}}
}

func defaultPrefix(v6 bool) netip.Prefix {
	if v6 {
		return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}
	return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
}

// familyPrefixes returns the interface's addresses usable for v6 or v4
// egress (IPv6 link-local only addresses cannot carry it), sorted.
func familyPrefixes(iface ScopedInterface, v6 bool) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range iface.Prefixes {
		a := p.Addr().Unmap()
		if a.Is6() != v6 || a.IsLoopback() || (v6 && a.IsLinkLocalUnicast()) {
			continue
		}
		out = append(out, netip.PrefixFrom(a, p.Bits()))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func (r rememberedGateway) validFor(prefixes []netip.Prefix) bool {
	if !r.gateway.IsValid() || !slices.Equal(r.prefixes, prefixes) {
		return false
	}
	if r.gateway.Is4() {
		for _, p := range prefixes {
			if p.Masked().Contains(r.gateway) {
				return true
			}
		}
		return false
	}
	// IPv6 routers are usually link-local: valid while the interface keeps
	// the same global addresses (the same network).
	return true
}

// plan decides the scoped default of every eligible interface. owned holds
// routes Yuhaiin installed earlier. It returns the plan, routes to create and
// owned routes to delete. A route of ours whose interface changed network is
// stale: it is deleted, and recreated only once the new router is known.
func (p *scopedPlanner) plan(rib []RIBRoute, ifaces []ScopedInterface, owned map[scopedKey]ownedScoped) (plan []ScopedRoute, create []ScopedRoute, remove []ScopedRoute) {
	keep := map[scopedKey]bool{}
	for _, iface := range ifaces {
		if !iface.Up || iface.Loopback || iface.OwnTun {
			continue
		}
		for _, v6 := range []bool{false, true} {
			prefixes := familyPrefixes(iface, v6)
			if len(prefixes) == 0 {
				continue
			}
			key := scopedKey{iface.Index, v6}
			def := defaultPrefix(v6)
			r := ScopedRoute{Interface: iface.Name, Index: iface.Index, IPv6: v6}
			var scoped, global *RIBRoute
			for i := range rib {
				e := &rib[i]
				if e.Index != iface.Index || e.Dst != def {
					continue
				}
				if e.Scoped {
					scoped = e
				} else if e.Gateway.IsValid() {
					global = e
				}
			}
			switch {
			case scoped != nil:
				o, ours := owned[key]
				ours = ours && o.gateway == scoped.Gateway
				if ours && !slices.Equal(o.prefixes, prefixes) {
					// Ours, but for the previous network.
					delete(p.remembered, key)
					r.State = ScopedUnavailable
					r.Reason = "interface changed network; waiting for its router"
					break
				}
				r.Gateway, r.Link = scoped.Gateway, !scoped.Gateway.IsValid()
				r.State = ScopedBorrowed
				if ours {
					r.State = ScopedOwned
					keep[key] = true
				}
				if scoped.Gateway.IsValid() {
					p.remembered[key] = rememberedGateway{scoped.Gateway, prefixes}
				}
			case global != nil:
				r.Gateway, r.State = global.Gateway, ScopedPrimary
				p.remembered[key] = rememberedGateway{global.Gateway, prefixes}
			default:
				if m, ok := p.remembered[key]; ok && m.validFor(prefixes) {
					r.Gateway, r.State = m.gateway, ScopedOwned
					keep[key] = true
					if o, ok := owned[key]; !ok || o.gateway != m.gateway {
						create = append(create, r)
					}
				} else {
					delete(p.remembered, key)
					r.State = ScopedUnavailable
					r.Reason = "no router known for this interface"
				}
			}
			plan = append(plan, r)
		}
	}
	for key, o := range owned {
		if !keep[key] {
			remove = append(remove, ScopedRoute{Index: key.index, IPv6: key.v6, Gateway: o.gateway})
		}
	}
	sort.Slice(remove, func(i, j int) bool {
		if remove[i].Index != remove[j].Index {
			return remove[i].Index < remove[j].Index
		}
		return !remove[i].IPv6
	})
	return plan, create, remove
}

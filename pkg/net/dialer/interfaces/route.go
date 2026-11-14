package interfaces

import (
	"maps"
	"net/netip"
	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie/cidr"
)

// rtInfo contains information on a single route.
type rtInfo struct {
	Dst         netip.Prefix
	OutputIface string
	Gateway     netip.Addr
	// Metric orders routes with the same prefix, lower first (Windows:
	// route metric plus interface metric). Zero where the OS orders them.
	Metric uint32
}

type router struct {
	v4, v6 []rtInfo
	// scoped are macOS interface-scoped routes to directly attached networks
	// (no default, no gateway). They never enter the trie, where they could
	// replace the global choice, but a destination inside one is reachable
	// only through that interface.
	scoped []rtInfo
}

// equal compares the full route snapshot, including gateways and entry order.
func (r router) equal(other router) bool {
	return slices.Equal(r.v4, other.v4) && slices.Equal(r.v6, other.v6) && slices.Equal(r.scoped, other.scoped)
}

// sameTrie compares only data used by ToTrie. Distinct prefix ordering and
// gateway changes cannot affect lookup results; the last entry still wins
// when a prefix is duplicated.
func (r router) sameTrie(other router) bool {
	if r.equal(other) {
		return true
	}
	mapping := func(routes router) map[netip.Prefix]string {
		result := make(map[netip.Prefix]string, len(routes.v4)+len(routes.v6))
		for _, entry := range routes.v4 {
			result[entry.Dst.Masked()] = entry.OutputIface
		}
		for _, entry := range routes.v6 {
			result[entry.Dst.Masked()] = entry.OutputIface
		}
		return result
	}
	return maps.Equal(mapping(r), mapping(other))
}

func (r router) ToTrie() *cidr.Cidr[string] {
	c := cidr.NewTrie[string]()
	for _, v := range r.v4 {
		c.InsertCIDR(v.Dst, v.OutputIface)
	}
	for _, v := range r.v6 {
		c.InsertCIDR(v.Dst, v.OutputIface)
	}
	return c
}

func interfacesMap() (map[int]Interface, error) {
	ifaces, err := GetInterfaceList()
	if err != nil {
		return nil, err
	}
	return interfacesMapFrom(ifaces), nil
}

func interfacesMapFrom(ifaces []Interface) map[int]Interface {
	ifces := make(map[int]Interface, len(ifaces))
	for _, iface := range ifaces {
		ifces[iface.Index] = iface
	}
	return ifces
}

func routes() (router, error) {
	ifaces, err := interfacesMap()
	if err != nil {
		return router{}, err
	}
	return routesFrom(ifaces)
}

// RouteChoice is the route Egress Selection picked for a destination.
type RouteChoice struct {
	Interface string
	Prefix    netip.Prefix
	Gateway   netip.Addr
	Metric    uint32
}

// selectRoute returns the most specific route for dst whose interface is not
// excluded; equal prefixes prefer the lower metric, then the later entry
// (matching the trie, where the last insert wins).
func (r router) selectRoute(dst netip.Addr, exclude func(string) bool) (RouteChoice, bool) {
	dst = dst.Unmap()
	list := r.v4
	if dst.Is6() {
		list = r.v6
	}
	best := -1
	for i, route := range list {
		if !route.Dst.Contains(dst) || (exclude != nil && exclude(route.OutputIface)) {
			continue
		}
		if best < 0 {
			best = i
			continue
		}
		b := list[best]
		switch {
		case route.Dst.Bits() > b.Dst.Bits():
			best = i
		case route.Dst.Bits() == b.Dst.Bits() && route.Metric <= b.Metric:
			best = i
		}
	}
	for _, route := range r.scoped {
		if !route.Dst.Contains(dst) || (exclude != nil && exclude(route.OutputIface)) {
			continue
		}
		if best < 0 || route.Dst.Bits() > list[best].Dst.Bits() {
			return RouteChoice{Interface: route.OutputIface, Prefix: route.Dst}, true
		}
	}
	if best < 0 {
		return RouteChoice{}, false
	}
	return RouteChoice{Interface: list[best].OutputIface, Prefix: list[best].Dst, Gateway: list[best].Gateway, Metric: list[best].Metric}, true
}

func (r router) defaults() []RouteChoice {
	var out []RouteChoice
	for _, list := range [][]rtInfo{r.v4, r.v6} {
		for _, route := range list {
			if route.Dst.Bits() == 0 {
				out = append(out, RouteChoice{Interface: route.OutputIface, Prefix: route.Dst, Gateway: route.Gateway, Metric: route.Metric})
			}
		}
	}
	return out
}

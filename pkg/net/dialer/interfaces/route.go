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
}

type router struct {
	v4, v6 []rtInfo
}

// equal compares the full route snapshot, including gateways and entry order.
func (r router) equal(other router) bool {
	return slices.Equal(r.v4, other.v4) && slices.Equal(r.v6, other.v6)
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

	ifces := make(map[int]Interface, len(ifaces))
	for _, iface := range ifaces {
		ifces[iface.Index] = iface
	}

	return ifces, nil
}

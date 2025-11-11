package interfaces

import (
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie/cidr"
)

// rtInfo contains information on a single route.
type rtInfo struct {
	Dst         netip.Prefix
	OutputIface string
}

type router struct {
	v4, v6 []rtInfo
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

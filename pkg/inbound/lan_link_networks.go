package inbound

import (
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strings"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
)

// Interfaces that carry tunnels, containers or virtual switches rather than a
// physical LAN. They are never offered as candidates; a user can still type
// their CIDR manually.
var virtualInterfacePrefixes = []string{
	"lo", "docker", "br-", "veth", "virbr", "vmnet", "vboxnet", "tun", "tap", "wg", "utun", "ppp",
	"tailscale", "zt", "ipsec", "cni", "flannel", "kube", "podman", "cali", "awdl", "llw", "vethernet",
	"nordlynx", "ham", "dummy", "ifb", "gif", "stf", "anpi", "ap",
}

type interfaceNetwork struct {
	name   string
	flags  net.Flags
	prefix netip.Prefix
}

// detectLANLinkNetworks lists the networks of up, non-virtual interfaces.
func detectLANLinkNetworks() contract.LANLinkNetworks {
	switch runtime.GOOS {
	case "android", "ios", "js", "wasip1":
		return contract.LANLinkNetworks{Supported: false, Items: []contract.LANLinkNetwork{},
			Reason: "Network detection is not available on " + runtime.GOOS + "; enter the networks manually."}
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return contract.LANLinkNetworks{Supported: false, Items: []contract.LANLinkNetwork{}, Reason: "Network detection failed: " + err.Error()}
	}
	var found []interfaceNetwork
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if prefix, err := netip.ParsePrefix(addr.String()); err == nil {
				found = append(found, interfaceNetwork{name: iface.Name, flags: iface.Flags, prefix: prefix})
			}
		}
	}
	return contract.LANLinkNetworks{Supported: true, Items: classifyLANNetworks(found)}
}

func classifyLANNetworks(found []interfaceNetwork) []contract.LANLinkNetwork {
	items := []contract.LANLinkNetwork{}
	for _, n := range found {
		lower := strings.ToLower(n.name)
		if n.flags&net.FlagUp == 0 || n.flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 ||
			slices.ContainsFunc(virtualInterfacePrefixes, func(p string) bool { return strings.HasPrefix(lower, p) }) {
			continue
		}
		addr := n.prefix.Addr().Unmap()
		if n.prefix.Addr().Is4In6() || !addr.IsValid() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
			addr.IsMulticast() || addr.IsUnspecified() || n.prefix.Bits() >= addr.BitLen() || n.prefix.Bits() == 0 {
			continue
		}
		network := n.prefix.Masked()
		family := "ipv4"
		if addr.Is6() {
			family = "ipv6"
		}
		cidr := network.String()
		if slices.ContainsFunc(items, func(i contract.LANLinkNetwork) bool { return i.CIDR == cidr }) {
			continue
		}
		items = append(items, contract.LANLinkNetwork{CIDR: cidr, Interface: n.name, Family: family})
	}
	slices.SortFunc(items, func(a, b contract.LANLinkNetwork) int {
		return strings.Compare(a.Interface+a.CIDR, b.Interface+b.CIDR)
	})
	return items
}

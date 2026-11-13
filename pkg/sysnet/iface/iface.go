// Package iface discovers network interfaces, their addresses and gateways
// for the System Network Manager. Indexes are runtime values: callers persist
// interface names (and hardware addresses) and resolve them on every use.
package iface

import (
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
)

// Interface types.
const (
	TypeLoopback = "loopback"
	TypeEthernet = "ethernet"
	TypeWiFi     = "wifi"
	TypeTunnel   = "tunnel" // TUN, WireGuard, Tailscale, utun, PPP and other point-to-point links
	TypeBridge   = "bridge"
	TypeVirtual  = "virtual" // veth, dummy, VLAN and similar
	TypeOther    = "other"
)

// Info describes one interface.
type Info struct {
	Name         string
	Index        int
	Type         string
	Up           bool
	MTU          int
	HardwareAddr string
	PointToPoint bool
	Addresses    []netip.Prefix
	// Gateway and GatewayV6 are next hops of routes through this interface
	// found in the main routing table (the default route first).
	Gateway   netip.Addr
	GatewayV6 netip.Addr
}

// HasFamily reports whether the interface has a usable address of the family.
func (i Info) HasFamily(v6 bool) bool {
	for _, p := range i.Addresses {
		a := p.Addr()
		if a.Is4() != v6 && (!v6 || !a.IsLinkLocalUnicast()) {
			return true
		}
	}
	return false
}

// OnLink reports whether gateway is inside one of the interface's subnets, or
// is an IPv6 link-local address. A gateway elsewhere is not directly
// reachable and must not be used as a next hop on this interface.
func (i Info) OnLink(gateway netip.Addr) bool {
	if gateway.Is6() && gateway.IsLinkLocalUnicast() {
		return true
	}
	for _, p := range i.Addresses {
		if p.Contains(gateway) && p.Addr() != gateway {
			return true
		}
	}
	return false
}

// NeedsGateway reports whether routes through the interface need a next hop:
// broadcast links (Ethernet, Wi-Fi, bridges) do, point-to-point links do not.
func (i Info) NeedsGateway() bool {
	switch i.Type {
	case TypeTunnel, TypeLoopback:
		return false
	}
	return !i.PointToPoint
}

// List returns the current interfaces sorted by index. It uses the shared
// interface source, which on Android is provided by the app: Android 11+
// denies apps the netlink dumps net.Interfaces needs.
func List() ([]Info, error) {
	list, err := interfaces.GetInterfaceList()
	if err != nil {
		return nil, err
	}
	gateways := platformGateways()
	out := make([]Info, 0, len(list))
	for _, item := range list {
		if item.Interface == nil {
			continue
		}
		ifc := *item.Interface
		info := Info{
			Name:         ifc.Name,
			Index:        ifc.Index,
			Up:           ifc.Flags&net.FlagUp != 0,
			MTU:          ifc.MTU,
			HardwareAddr: ifc.HardwareAddr.String(),
			PointToPoint: ifc.Flags&net.FlagPointToPoint != 0,
		}
		if addrs, err := item.Addrs(); err == nil {
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok {
					ip, ok := netip.AddrFromSlice(n.IP)
					if !ok {
						continue
					}
					bits, _ := n.Mask.Size()
					info.Addresses = append(info.Addresses, netip.PrefixFrom(ip.Unmap(), bits))
				}
			}
		}
		info.Type = classify(ifc, platformType(ifc))
		if gw, ok := gateways[ifc.Index]; ok {
			info.Gateway, info.GatewayV6 = gw[0], gw[1]
		}
		out = append(out, info)
	}
	slices.SortFunc(out, func(a, b Info) int { return a.Index - b.Index })
	return out, nil
}

// classify combines a platform hint with name and flag heuristics.
func classify(ifc net.Interface, hint string) string {
	if ifc.Flags&net.FlagLoopback != 0 {
		return TypeLoopback
	}
	if hint != "" {
		return hint
	}
	name := strings.ToLower(ifc.Name)
	for _, prefix := range []string{"utun", "tun", "tap", "wg", "tailscale", "zt", "ppp", "ipsec", "gif", "stf", "wintun", "wireguard"} {
		if strings.HasPrefix(name, prefix) {
			return TypeTunnel
		}
	}
	if ifc.Flags&net.FlagPointToPoint != 0 {
		return TypeTunnel
	}
	switch {
	case strings.HasPrefix(name, "br") || strings.HasPrefix(name, "bridge") || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "podman") || strings.HasPrefix(name, "virbr"):
		return TypeBridge
	case strings.HasPrefix(name, "wl") || strings.HasPrefix(name, "wlan") || strings.Contains(name, "wi-fi") || strings.Contains(name, "wireless"):
		return TypeWiFi
	case strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "awdl") || strings.HasPrefix(name, "llw") || strings.HasPrefix(name, "anpi") || strings.HasPrefix(name, "dummy"):
		return TypeVirtual
	case strings.HasPrefix(name, "en") || strings.HasPrefix(name, "eth") || strings.Contains(name, "ethernet"):
		return TypeEthernet
	}
	if len(ifc.HardwareAddr) == 6 {
		return TypeEthernet
	}
	return TypeOther
}

// Find resolves a saved interface: by name, or by hardware address after a
// rename.
func Find(list []Info, name, hardwareAddr string) (Info, bool) {
	for _, i := range list {
		if i.Name == name {
			return i, true
		}
	}
	if hardwareAddr != "" {
		for _, i := range list {
			if strings.EqualFold(i.HardwareAddr, hardwareAddr) {
				return i, true
			}
		}
	}
	return Info{}, false
}

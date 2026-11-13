package sysnet

import (
	"runtime"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
)

// PlatformCapabilities describes what the adapters of goos can apply.
//
//   - Linux: a dedicated policy-routing table for any interface, kernel
//     forwarding, nftables masquerade and TProxy interception.
//   - macOS and Windows: routes to any interface in the single system table;
//     no policy routing and no forwarding management.
//   - Android: routes of the Yuhaiin VPN only, applied by VpnService.
func PlatformCapabilities(goos string, routes, forwarding bool) sysnet.Capabilities {
	c := sysnet.Capabilities{Platform: goos, RouteTargets: []string{}, ForwardTargets: []string{}}
	switch goos {
	case "android":
		c.RouteManagement = true
		c.RouteTargets = []string{sysnet.TargetTunInbound}
		return c
	case "linux", "darwin", "windows":
		if !routes {
			return c
		}
		c.RouteManagement, c.MultipleTargets, c.ExternalInterfaces, c.Gateways = true, true, true, true
		c.RouteTargets = []string{sysnet.TargetTunInbound, sysnet.TargetInterface}
		if goos == "linux" {
			c.PolicyRouting = true
			if forwarding {
				c.IPv4Forwarding, c.IPv6Forwarding, c.NAT, c.TProxy = true, true, true, true
				c.ForwardTargets = []string{sysnet.TargetTunInbound, sysnet.TargetInterface, sysnet.TargetTProxy}
			}
		}
	}
	return c
}

// CurrentPlatform is runtime.GOOS.
func CurrentPlatform() string { return runtime.GOOS }

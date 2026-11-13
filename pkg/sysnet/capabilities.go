package sysnet

import (
	"runtime"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
)

// PlatformCapabilities describes what the adapters of goos can apply.
//
//   - Linux: a dedicated policy-routing table for any interface, kernel
//     forwarding, nftables masquerade and TProxy interception.
//   - macOS: routes to any interface in the single system table; forwarding
//     with a PF anchor (source restriction, per-rule egress, NAT).
//   - Windows: routes per interface; forwarding per interface that follows
//     the routing table, without source filtering or NAT.
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
		if !forwarding {
			return c
		}
		c.IPv4Forwarding, c.IPv6Forwarding = true, true
		switch goos {
		case "linux":
			c.PolicyRouting = true
			c.NAT, c.TProxy, c.ForwardSourceFilter = true, true, true
			c.ForwardTargets = []string{sysnet.TargetTunInbound, sysnet.TargetInterface, sysnet.TargetRoutes, sysnet.TargetTProxy}
		case "darwin":
			c.NAT, c.ForwardSourceFilter = true, true
			c.ForwardTargets = []string{sysnet.TargetTunInbound, sysnet.TargetInterface, sysnet.TargetRoutes}
		case "windows":
			c.ForwardTargets = []string{sysnet.TargetRoutes}
		}
	}
	return c
}

// CurrentPlatform is runtime.GOOS.
func CurrentPlatform() string { return runtime.GOOS }

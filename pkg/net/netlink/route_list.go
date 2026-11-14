package netlink

import (
	"errors"
	"net/netip"
)

// RouteEntry is one route of the operating system routing table, read-only.
type RouteEntry struct {
	Destination netip.Prefix
	Gateway     netip.Addr
	Link        int
	Table       int
	Metric      int
	// Protocol is the Linux rtm_protocol; RouteProtocolYuhaiin marks routes
	// this process installs.
	Protocol int
	// Type is "unicast", "local", "blackhole", ... where the OS reports it.
	Type string
	// Interface names the interface when Link is unknown (Android).
	Interface string
	// OwnVPN marks routes of this app's own VPN network (Android).
	OwnVPN bool
}

// AltListRoutes replaces reading the kernel routing table where apps may
// not (Android): the app reports the routes of each network instead.
var AltListRoutes func() ([]RouteEntry, error)

// PolicyRuleEntry is one Linux policy routing rule, read-only.
type PolicyRuleEntry struct {
	Priority int
	Family   int // 4 or 6
	Selector string
	Table    int
	Protocol int
}

// RouteProtocolYuhaiin is the rtm_protocol of routes and rules Yuhaiin owns.
const RouteProtocolYuhaiin = 0xa5

// ErrRouteListUnsupported is returned where apps cannot read the routing
// table (Android).
var ErrRouteListUnsupported = errors.New("this platform does not allow reading the routing table")

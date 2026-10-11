package dataplane

import "net"

// The client-side networking a caller applies to a client.Result, described
// once for every platform.
//
// The description is portable; installing it is not. ClientRouter is
// implemented per platform -- iproute2 on Linux, ifconfig/route/networksetup on
// macOS, and a stub that says "not supported here" everywhere else -- but every
// one of them takes this struct, so cmd/veepin and the NetworkManager plugin
// build the same thing whatever they are running on.
//
// Before the split, client_route.go carried no build tag at all. It compiled
// everywhere and failed at run time with `exec: "ip": executable file not
// found` -- which reads as a broken installation rather than as "this platform
// is not supported", and is the wrong answer next to tun_other.go's clean
// "not supported on darwin (Linux only)".

// ClientNetConfig describes the networking changes needed to route a host's
// traffic through the VPN: the TUN interface, the address assigned by the
// server, and the server's public address (which must remain reachable via the
// physical link so ESP packets don't recurse into the tunnel).
type ClientNetConfig struct {
	TUNName     string
	AssignedIP  net.IP
	Netmask     net.IP
	AssignedIP6 net.IP   // internal IPv6 address (dual-stack), or nil
	Prefix6     int      // IPv6 prefix length for AssignedIP6
	ServerIP    net.IP   // VPN server's public IP (host route added outside tunnel)
	DNS         []net.IP // resolvers to install for the tunnel; see client_dns.go
	// NoDNS leaves the host's resolver configuration alone. It is for the
	// operator who manages their own resolver and does not want a VPN client
	// editing it -- not a default, because the default that skips DNS is the
	// one that leaks every query while the tunnel looks fine.
	NoDNS bool
	// FullTunnel routes all traffic through the VPN (default route). When false,
	// only the assigned subnet is routed, plus whatever Routes names.
	FullTunnel bool

	// Routes are extra destinations to send through the tunnel, for a split
	// tunnel that wants to name what it carries. Before this, -full-tunnel=false
	// brought the interface up and left the operator at a shell with `ip route`,
	// which is a reasonable thing to offer and not a feature.
	Routes []*net.IPNet
	// Excludes are destinations to keep OFF the tunnel, installed as
	// more-specific routes via the physical gateway. It is the same mechanism as
	// the server host route above -- a /32 beats a /1 -- and shares its code, so
	// the one thing that has to stay true of both stays true in one place.
	Excludes []*net.IPNet
}

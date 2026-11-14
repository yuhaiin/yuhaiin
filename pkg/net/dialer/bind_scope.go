package dialer

import "net"

// skipInterfaceBind reports whether a socket whose Control address is address
// must stay unbound. Loopback, link-local and similar scoped addresses never
// leave through the outbound interface. The wildcard address does: a listen
// socket on 0.0.0.0 or :: (for example Tailscale's magicsock) still egresses
// by the routing table, so leaving it unbound lets its packets follow the
// default route into our own TUN and be rejected as a loop.
func skipInterfaceBind(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && !ip.IsUnspecified() && !ip.IsGlobalUnicast()
}

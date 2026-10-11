package dataplane

import "net"

// The DNS backend contract, described once for every platform. What implements
// it is per platform: resolvectl or /etc/resolv.conf on Linux, networksetup on
// macOS, nothing anywhere else.
//
// Why a client installs resolvers at all is in client_dns_linux.go's header,
// and it is the same reason on every platform: a full-tunnel VPN that keeps the
// host's old resolver leaks every query it was meant to hide, in plaintext,
// from the host's real address -- while the user believes otherwise.

// dnsBackend installs and removes the tunnel's resolver configuration. apply is
// called once, after the interface is up; revert is called at most once and is
// a no-op if apply never succeeded.
type dnsBackend interface {
	apply(tun string, servers []net.IP, fullTunnel bool) error
	revert() error
	// name identifies the backend in log lines, so an operator can tell which
	// of the two mechanisms touched their host.
	name() string
}

// execRunner runs a command and returns its combined output on failure. It is a
// variable so the backends' command construction can be tested without a
// systemd on the machine running the tests.
type execRunner func(args []string) error

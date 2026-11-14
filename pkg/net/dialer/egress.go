package dialer

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
)

// Egress Selection decides which interface a socket is bound to.
//
// An explicit interface (the context's BindInterface, a fixed outbound's
// interface, or a configured network interface) always wins: it means "use
// exactly this interface". Otherwise the choice is automatic:
//
//   - while no TUN of ours is up, sockets follow the OS routing table unbound;
//   - with a working routing mark (Linux), the kernel routes protected
//     sockets per packet, so they stay unbound;
//   - otherwise (macOS, Windows, Android, or Linux without SO_MARK) the
//     socket is bound to the interface the OS would use for the destination
//     with our TUN excluded. That binding is what keeps it out of the TUN.

// ErrNoEgress is returned when our TUN is up and no other interface routes
// the destination; sending anyway would loop.
var ErrNoEgress = errors.New("no egress interface outside the TUN")

// ConfiguredInterface is the user's fixed outbound interface, or "".
var ConfiguredInterface = func() string { return "" }

// Route sources, replaceable in tests.
var (
	selectRoute      = interfaces.SelectRoute
	defaultInterface = interfaces.DefaultInterfaceName
)

// ownTunActive reports whether a TUN of ours exists, i.e. whether an unbound,
// unmarked socket could be routed back into this process.
func ownTunActive() bool { return SkipInterface().Len() > 0 }

func isOwnTun(name string) bool { return name != "" && SkipInterface().Has(name) }

// explicitInterface returns the interface a caller pinned, if any.
func explicitInterface(contextInterface, optionInterface string) string {
	if contextInterface != "" {
		return contextInterface
	}
	if optionInterface != "" {
		return optionInterface
	}
	return ConfiguredInterface()
}

// bindsAutomatically reports whether this platform must bind sockets to keep
// them out of the TUN, given whether the protector succeeded.
func bindsAutomatically(protected bool) bool {
	switch runtime.GOOS {
	case "linux":
		return !protected
	case "android":
		// VpnService.protect plus Android Network binding; keep the
		// interface choice the platform adapters expect.
		return true
	default:
		return true
	}
}

// autoEgress picks the interface for dst with our TUN excluded. An invalid
// dst (a listen socket without a destination hint) takes the default route.
func autoEgress(dst netip.Addr) (string, error) {
	if dst.IsValid() {
		dst = dst.Unmap()
		if !dst.IsGlobalUnicast() {
			// Loopback, link-local and multicast are scoped: never bound.
			return "", nil
		}
		if choice, ok := selectRoute(dst, isOwnTun); ok {
			return choice.Interface, nil
		}
	}
	name := defaultInterface()
	if name == "" || isOwnTun(name) {
		return "", fmt.Errorf("%w: destination %v", ErrNoEgress, dst)
	}
	return name, nil
}

// GetInterfaceByIP returns the interface the OS would use for ip outside our
// TUN. It is used by sockets created outside the dialer (ICMP).
func GetInterfaceByIP(ip []byte) (string, error) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return "", fmt.Errorf("invalid address %v", ip)
	}
	return autoEgress(addr)
}

// resolveEgress decides the interface name to bind, or "" for none, for a
// socket that was (protected) or was not protected.
func resolveEgress(explicit string, dst netip.Addr, protected bool) (string, error) {
	if explicit != "" {
		if isOwnTun(explicit) {
			return "", fmt.Errorf("block dial to skip infinite loop: iface: %s, addr: %v", explicit, dst)
		}
		return explicit, nil
	}
	if !ownTunActive() && runtime.GOOS != "android" {
		return "", nil
	}
	if !bindsAutomatically(protected) {
		return "", nil
	}
	return autoEgress(dst)
}

package dialer

import (
	"github.com/Asutorufa/yuhaiin/pkg/log"
)

// applySocketRouting runs in Control, after the socket exists and before it
// connects or binds: protection first, then egress binding.
//
// address is the remote address for dialed sockets and the local address for
// listen-style ones.
func applySocketRouting(network, address string, fd uintptr, opts *Options) error {
	_, protectErr := protectSocket(fd)
	if opts.listener {
		// Listeners are protected so replies to clients never enter our
		// TUN, and never bound: they must accept on every interface.
		if protectErr != nil {
			log.Warn("listener socket not protected", "addr", address, "err", protectErr)
		}
		return nil
	}

	iface := opts.InterfaceName
	if protectErr != nil && !opts.explicit {
		// The mark failed after Egress Selection expected it to work. Bind
		// instead, which is safe as long as the interface is not our TUN.
		fallback, err := resolveEgress("", opts.egressDst, false)
		if err != nil {
			return protectErr
		}
		iface = fallback
		opts.InterfaceName = fallback
	}
	if protectErr != nil && iface == "" && ownTunActive() && opts.egressDst.IsGlobalUnicast() {
		// Neither protected nor bound while our TUN can capture it.
		return protectErr
	}

	if iface == "" || skipInterfaceBind(address) {
		return nil
	}
	return BindInterface(network, fd, iface)
}

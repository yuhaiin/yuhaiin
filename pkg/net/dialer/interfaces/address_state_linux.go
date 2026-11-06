//go:build !android

package interfaces

import (
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func usableLinuxAddress(flags int) bool {
	// Deprecated addresses can still support established connections. Optimistic
	// DAD explicitly permits use before DAD finishes; tentative alone does not.
	return flags&unix.IFA_F_DADFAILED == 0 && (flags&unix.IFA_F_TENTATIVE == 0 || flags&unix.IFA_F_OPTIMISTIC != 0)
}

func completeInterfaceNetwork(n *netstate.Network) error {
	addresses, err := netlink.AddrList(&netlink.Device{Index: n.Index}, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	usable := make(map[netip.Addr]bool, len(addresses))
	for _, address := range addresses {
		if ip, ok := netip.AddrFromSlice(address.IP); ok && usableLinuxAddress(address.Flags) {
			usable[ip.Unmap()] = true
		}
	}
	retained := n.Addresses[:0]
	for _, ip := range n.Addresses {
		if usable[ip] {
			retained = append(retained, ip)
		}
	}
	n.Addresses = retained
	return nil
}

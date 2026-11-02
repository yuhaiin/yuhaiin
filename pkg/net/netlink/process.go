package netlink

import (
	"errors"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

var (
	addrV4Loopback = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	addrV6Loopback = netip.IPv6Loopback()
)

// ProcessAddrs converts a flow's endpoints into socket lookup keys. An
// unspecified destination is treated as loopback, which is where a socket
// connected to the wildcard address is bound.
func ProcessAddrs(src, dst netapi.Address) (ip, to netip.AddrPort, err error) {
	if src.IsFqdn() || dst.IsFqdn() {
		return ip, to, errors.New("source or destination address is not ip")
	}

	ip = src.(netapi.IPAddress).AddrPort()
	to = dst.(netapi.IPAddress).AddrPort()

	if to.Addr().IsUnspecified() {
		if ip.Addr().Is4() {
			to = netip.AddrPortFrom(addrV4Loopback, dst.Port())
		} else {
			to = netip.AddrPortFrom(addrV6Loopback, dst.Port())
		}
	}
	return ip, to, nil
}

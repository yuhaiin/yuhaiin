//go:build !linux

package device

import "github.com/Asutorufa/yuhaiin/pkg/net/netlink"

// Native Windows and utun readers already expose complete IP packets through
// the existing offset-aware wrapper. Android uses the Linux fd implementation.
func OpenPacketWriter(sc netlink.TunScheme, mtu int) (netlink.Tun, error) { return OpenWriter(sc, mtu) }

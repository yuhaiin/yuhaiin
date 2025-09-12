//go:build !linux && (!unix || aix || ppc64) && !windows

package device

import (
	"errors"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
)

func OpenWriter(sc netlink.TunScheme, mtu int) (netlink.Tun, error) {
	return nil, errors.ErrUnsupported
}

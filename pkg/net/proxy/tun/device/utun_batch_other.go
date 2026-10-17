//go:build unix && !aix && !ppc64 && !linux && (!darwin || ios)

package device

import "github.com/Asutorufa/yuhaiin/pkg/net/netlink"

func experimentalUTUN(d *wgDevice, _ bool) netlink.Tun { return d }

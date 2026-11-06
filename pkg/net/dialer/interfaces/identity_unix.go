//go:build !windows

package interfaces

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
	"strconv"
)

func stableInterfaceID(iface Interface) (string, error) {
	if iface.Index <= 0 {
		return "", nil
	}
	// Scoped to this monitor's network namespace. Deletion notifications and
	// unavailable snapshots retire a lifetime before an index can be reused.
	return "ifindex:" + strconv.Itoa(iface.Index), nil
}

func completeInterfaceNetwork(*netstate.Network) error { return nil }

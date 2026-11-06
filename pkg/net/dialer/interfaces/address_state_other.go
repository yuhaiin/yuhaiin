//go:build (!linux || android) && !windows

package interfaces

import "github.com/Asutorufa/yuhaiin/pkg/net/netstate"

func completeInterfaceNetwork(*netstate.Network) error { return nil }

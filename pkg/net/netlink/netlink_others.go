//go:build (!linux || android) && !darwin && !windows
// +build !linux android
// +build !darwin
// +build !windows

package netlink

import (
	"errors"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func FindProcessName(network string, ip netip.AddrPort, to netip.AddrPort) (netapi.Process, error) {
	return netapi.Process{}, errors.New("not implemented")
}

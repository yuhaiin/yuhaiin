//go:build !linux && !darwin && !windows
// +build !linux,!darwin,!windows

package netlink

import (
	"errors"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func FindProcessName(network string, ip netip.AddrPort, to netip.AddrPort) (netapi.Process, error) {
	return netapi.Process{}, errors.New("not implemented")
}

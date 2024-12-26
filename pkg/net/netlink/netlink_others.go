//go:build !linux && !darwin && !windows
// +build !linux,!darwin,!windows

package netlink

import (
	"errors"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func FindProcessName(network string, ip net.IP, srcPort uint16, to net.IP, toPort uint16) (netapi.Process, error) {
	return netapi.Process{}, errors.New("not implemented")
}

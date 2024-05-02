//go:build !linux && !darwin && !windows
// +build !linux,!darwin,!windows

package netlink

import (
	"errors"
	"net"
)

func FindProcessName(network string, ip net.IP, srcPort uint16, to net.IP, toPort uint16) (string, error) {
	return "", errors.New("not implemented")
}

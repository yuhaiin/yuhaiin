//go:build !darwin && !linux

package helper

import (
	"errors"
	"net"
)

func PeerUID(net.Conn) (int, error) {
	return -1, errors.New("peer credentials are not available on this platform")
}

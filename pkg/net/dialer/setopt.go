//go:build !linux && !darwin && !windows
// +build !linux,!darwin,!windows

package dialer

import "syscall"

func setSocketOptions(network, address string, c syscall.RawConn, opts *Options) error {
	return nil
}

func BindInterface(network string, fd uintptr, ifaceName string) error {
	return nil
}

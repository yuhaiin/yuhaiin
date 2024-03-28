//go:build !linux && !darwin && !windows
// +build !linux,!darwin,!windows

package netlink

func Route(opt *Options) error {
	return nil
}

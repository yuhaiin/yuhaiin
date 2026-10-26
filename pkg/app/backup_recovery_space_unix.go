//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package app

import "golang.org/x/sys/unix"

func recoveryAvailableBytes(directory string) (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(directory, &stat); err != nil {
		return 0, err
	}
	if stat.Bavail <= 0 || stat.Bsize <= 0 {
		return 0, nil
	}
	return uint64(stat.Bavail) * uint64(stat.Bsize), nil
}

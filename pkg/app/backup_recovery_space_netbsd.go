package app

import "golang.org/x/sys/unix"

func recoveryAvailableBytes(directory string) (uint64, error) {
	var stat unix.Statvfs_t
	if err := unix.Statvfs(directory, &stat); err != nil {
		return 0, err
	}
	return recoveryDiskBytes(stat.Bavail, stat.Frsize), nil
}

package backupfs

import "golang.org/x/sys/unix"

func recoveryAvailableBytes(directory string) (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(directory, &stat); err != nil {
		return 0, err
	}
	if stat.F_bavail <= 0 || stat.F_bsize == 0 {
		return 0, nil
	}
	return recoveryDiskBytes(uint64(stat.F_bavail), uint64(stat.F_bsize)), nil
}

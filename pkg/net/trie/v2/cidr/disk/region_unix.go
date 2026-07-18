//go:build aix || android || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package disk

import (
	"os"

	"golang.org/x/sys/unix"
)

func openRegion(path string) (*region, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if info.Size() <= 0 {
		_ = file.Close()
		return nil, os.ErrInvalid
	}
	data, err := unix.Mmap(int(file.Fd()), 0, int(info.Size()), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &region{data: data, file: file, size: uint64(info.Size())}, nil
}

func unmapBytes(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	return unix.Munmap(data)
}

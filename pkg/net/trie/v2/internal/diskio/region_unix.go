//go:build aix || android || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package diskio

import (
	"os"

	"golang.org/x/sys/unix"
)

func OpenRegion(path string) (*Region, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if info.Size() <= 0 {
		_ = f.Close()
		return nil, os.ErrInvalid
	}
	data, err := unix.Mmap(int(f.Fd()), 0, int(info.Size()), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Region{data: data, file: f, Size: uint64(info.Size())}, nil
}

// unmapBytes is the Unix half of the region lifecycle.
func unmapBytes(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	return unix.Munmap(data)
}

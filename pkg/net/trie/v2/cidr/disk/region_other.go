//go:build !aix && !android && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris

package disk

import "os"

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
	return &region{file: file, size: uint64(info.Size())}, nil
}

func unmapBytes(_ []byte) error { return nil }

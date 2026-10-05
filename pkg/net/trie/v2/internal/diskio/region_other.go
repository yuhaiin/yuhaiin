//go:build !aix && !android && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris

package diskio

import "os"

// Windows and other platforms use ReadAt rather than loading the whole index
// into the Go heap. The OS still provides its normal file cache.
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
	return &Region{file: f, Size: uint64(info.Size())}, nil
}

// unmapBytes is a no-op when the platform backend uses ReadAt.
func unmapBytes(_ []byte) error { return nil }

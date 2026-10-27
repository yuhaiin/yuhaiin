//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly && !windows

package backup

import "errors"

func recoveryAvailableBytes(string) (uint64, error) { return 0, errors.ErrUnsupported }

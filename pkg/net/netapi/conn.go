package netapi

import (
	"errors"
	"syscall"
)

func IsConnectionTimedout(err error) bool {
	if se, ok := errors.AsType[syscall.Errno](err); ok {
		if se == syscall.ETIMEDOUT {
			return true
		}
	}

	return false
}

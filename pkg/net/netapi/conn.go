package netapi

import (
	"errors"
	"syscall"
)

func IsConnectionTimedout(err error) bool {
	var se syscall.Errno

	if !errors.As(err, &se) {
		return false
	}

	return se == syscall.ETIMEDOUT
}

package netapi

import (
	"errors"
	"syscall"
)

func IsConnectionTimedout(err error) bool {
	se, ok := errors.AsType[syscall.Errno](err)
	return ok && se == syscall.ETIMEDOUT
}

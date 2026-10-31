//go:build !windows && !aix && !ppc64

package lockfile

import (
	"errors"
	"os"
	"syscall"
)

func LockFile(file *os.File) error {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOSYS) {
		return errors.Join(errors.ErrUnsupported, err)
	}
	return err
}

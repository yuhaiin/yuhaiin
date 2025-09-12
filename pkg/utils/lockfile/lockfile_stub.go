//go:build aix || ppc64

package lockfile

import (
	"errors"
	"os"
)

func LockFile(file *os.File) error {
	return errors.ErrUnsupported
}

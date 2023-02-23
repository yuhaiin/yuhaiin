//go:build !windows
// +build !windows

package lockfile

import (
	"os"
	"syscall"
)

func LockFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

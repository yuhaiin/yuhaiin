//go:build windows
// +build windows

package lockfile

import (
	"os"
	"syscall"
)

func LockFile(file *os.File) error {
	h, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		return err
	}
	defer syscall.FreeLibrary(h)

	addr, err := syscall.GetProcAddress(h, "LockFile")
	if err != nil {
		return err
	}

	r0, _, err := syscall.Syscall6(addr, 5, file.Fd(), 0, 0, 0, 1, 0)
	//fmt.Println(r0, r1, err)
	if int(r0) != 1 {
		return err
	}
	return nil
}

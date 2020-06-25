package process

import (
	"os"

	"github.com/Asutorufa/yuhaiin/config"
)

var (
	LockFilePath = config.Path + "/yuhaiin.lock"
	lockFile     *os.File
)

func GetProcessLock() error {
	var err error
	if lockFile, err = os.Create(LockFilePath); err != nil {
		return err
	}
	if err := LockFile(lockFile); err != nil {
		return err
	}
	return ProcessInit()
}

func LockFileClose() error {
	if err := lockFile.Close(); err != nil {
		return err
	}
	return os.Remove(LockFilePath)
}

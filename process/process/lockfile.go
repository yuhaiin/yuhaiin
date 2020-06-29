package process

import (
	"io/ioutil"
	"os"

	"github.com/Asutorufa/yuhaiin/config"
)

var (
	LockFilePath = config.Path + "/yuhaiin.lock"
	lockFile     *os.File
)

func GetProcessLock(str string) error {
	var err error
	tmp, _ := ReadLockFile()
	if lockFile, err = os.Create(LockFilePath); err != nil {
		return err
	}
	if err := LockFile(lockFile); err != nil {
		_, _ = lockFile.WriteString(tmp)
		return err
	}
	_, _ = lockFile.WriteString(str)
	return ProcessInit()
}

func ReadLockFile() (string, error) {
	s, err := ioutil.ReadFile(LockFilePath)
	if err != nil {
		return "", err
	}
	return string(s), nil
}

func LockFileClose() error {
	if err := lockFile.Close(); err != nil {
		return err
	}
	return os.Remove(LockFilePath)
}

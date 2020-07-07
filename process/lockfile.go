package process

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/Asutorufa/yuhaiin/config"
)

var (
	LockFilePath = config.Path + "/yuhaiin.lock"
	lockFile     *os.File
)

func GetProcessLock(str string) error {
	var err error
	lockFile, err = os.OpenFile(LockFilePath, os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return fmt.Errorf("GetProcessLock() -> OpenFile() -> %v", err)
	}
	if err := LockFile(lockFile); err != nil {
		return fmt.Errorf("GetProcessLock() -> LockFile() -> %v", err)
	}
	_, err = lockFile.WriteString(str)
	if err != nil {
		log.Printf("GetProcessLock() -> WriteString() -> %v", err)
	}
	return nil
}

func ReadLockFile() (string, error) {
	s, err := ioutil.ReadFile(LockFilePath)
	if err != nil {
		return "", fmt.Errorf("ReadLockFile() -> ReadFile() -> %v", err)
	}
	return string(s), nil
}

func LockFileClose() error {
	if err := lockFile.Close(); err != nil {
		return err
	}
	return os.Remove(LockFilePath)
}

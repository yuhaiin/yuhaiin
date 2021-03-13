package app

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"

	"github.com/Asutorufa/yuhaiin/config"
)

var (
	LockFilePath = config.Path + "/yuhaiin.lock"
	hostFile     = config.Path + "/host.txt"
	lockFile     *os.File
)

func GetProcessLock(str string) error {
	_, err := os.Stat(path.Dir(str))
	if err != nil && errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(path.Dir(LockFilePath), os.ModePerm)
		if err != nil {
			return fmt.Errorf("make dir failed: %v", err)
		}
	}

	lockFile, err = os.OpenFile(LockFilePath, os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return fmt.Errorf("open lock file failed: %v", err)
	}

	if err := LockFile(lockFile); err != nil {
		return fmt.Errorf("lock file failed: %v", err)
	}

	err = ioutil.WriteFile(hostFile, []byte(str), os.ModePerm)
	if err != nil {
		log.Printf("write host to file failed: %v", err)
	}
	return nil
}

func ReadLockFile() (string, error) {
	s, err := ioutil.ReadFile(hostFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read lock file failed: %v", err)
	}
	return string(s), nil
}

func LockFileClose() (erra error) {
	err := os.Remove(hostFile)
	if err != nil {
		erra = fmt.Errorf("%v\nremove host file failed: %v", erra, err)
	}
	err = lockFile.Close()
	if err != nil {
		erra = fmt.Errorf("%v\nunlock file failed: %v", erra, err)
	}
	err = os.Remove(LockFilePath)
	if err != nil {
		erra = fmt.Errorf("%v\nremove lock file failed: %v", erra, err)
	}
	return
}

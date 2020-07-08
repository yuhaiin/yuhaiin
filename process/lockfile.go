package process

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

var (
	LockFilePath = os.TempDir() + "/yuhaiin/yuhaiin.lock"
	hostFile     = os.TempDir() + "/yuhaiin/host.txt"
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

	err = ioutil.WriteFile(hostFile, []byte(str), os.ModePerm)
	// _, err = lockFile.WriteString(str)
	if err != nil {
		log.Printf("GetProcessLock() -> WriteString() -> %v", err)
	}
	return nil
}

func ReadLockFile() (string, error) {
	s, err := ioutil.ReadFile(hostFile)
	if err != nil {
		return "", fmt.Errorf("ReadLockFile() -> ReadFile() -> %v", err)
	}
	return string(s), nil
}

func LockFileClose() (erra error) {
	err := os.Remove(hostFile)
	if err != nil {
		fmt.Errorf("%v\nRemove hostFile -> %v", erra, err)
	}
	err = lockFile.Close()
	if err != nil {
		fmt.Errorf("%v\nUnlock File (close file) -> %v", erra, err)
	}
	err = os.Remove(LockFilePath)
	if err != nil {
		fmt.Errorf("%v\nRemove lockFile -> %v", erra, err)
	}
	return
}

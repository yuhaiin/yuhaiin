package app

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"unsafe"
)

type Lock struct {
	lockfile string
	lockFile *os.File

	locked bool
}

func NewLock(lockfile, payload string) (*Lock, error) {
	l := &Lock{lockfile: lockfile}

	return l, l.Lock(payload)
}

func (l *Lock) Lock(payload string) error {
	if l.locked {
		return nil
	}

	_, err := os.Stat(path.Dir(l.lockfile))
	if errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(path.Dir(l.lockfile), os.ModePerm)
		if err != nil {
			return fmt.Errorf("make dir failed: %v", err)
		}
	}

	l.lockFile, err = os.OpenFile(l.lockfile, os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return fmt.Errorf("open lock file failed: %v", err)
	}

	err = LockFile(l.lockFile)
	if err != nil {
		return fmt.Errorf("lock file failed: %v", err)
	}

	l.locked = true

	err = ioutil.WriteFile(l.lockfile+"_payload", []byte(payload), os.ModePerm)
	if err != nil {
		log.Printf("write host to file failed: %v", err)
	}
	return nil
}

func (l *Lock) Payload() (string, error) {
	s, err := ioutil.ReadFile(l.lockfile + "_payload")
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read lock file failed: %v", err)
	}
	return *(*string)(unsafe.Pointer(&s)), nil
}

func (l *Lock) UnLock() (erra error) {
	err := os.Remove(l.lockfile + "_payload")
	if err != nil {
		erra = fmt.Errorf("%v\nremove host file failed: %v", erra, err)
	}
	err = l.lockFile.Close()
	if err != nil {
		erra = fmt.Errorf("%v\nunlock file failed: %v", erra, err)
	}

	l.locked = false

	err = os.Remove(l.lockfile)
	if err != nil {
		erra = fmt.Errorf("%v\nremove lock file failed: %v", erra, err)
	}
	return
}

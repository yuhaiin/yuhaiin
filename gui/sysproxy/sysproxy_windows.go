package sysproxy

import (
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

func strPtr(s string) uintptr {
	return uintptr(unsafe.Pointer(syscall.StringBytePtr(s)))
}

func getExecPath() (string, error) {
	file, err := exec.LookPath(os.Args[0])
	if err != nil {
		return "", err
	}
	execPath, err := filepath.Abs(file)
	if err != nil {
		return "", err
	}
	return execPath, nil
}

func getSysProxy() (*syscall.LazyDLL, error) {
	execPath, err := getExecPath()
	if err != nil {
		return nil, err
	}
	var dll string
	if runtime.GOARCH == "amd64" {
		dll = filepath.Dir(execPath) + "\\static\\dll\\x64\\sysproxydll.dll"
	} else if runtime.GOARCH == "386" {
		dll = filepath.Dir(execPath) + "\\static\\dll\\x86\\sysproxydll.dll"
	} else {
		return nil, errors.New("not support " + runtime.GOARCH)
	}

	fmt.Println("System Proxy DLL:", dll)
	return syscall.NewLazyDLL(dll), nil
}

func SetSysProxy(http, _ string) {
	urls, err := url.Parse("//" + http)
	if err != nil {
		log.Println(err)
		return
	}
	sysproxy, err := getSysProxy()
	if err != nil {
		log.Println(err)
		return
	}
	setSysProxy := sysproxy.NewProc("SetSystemProxy")
	ret, _, e1 := syscall.Syscall(setSysProxy.Addr(), 3, strPtr(urls.Hostname()), strPtr(urls.Port()), strPtr(""))
	if ret == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Printf("%d.%d", byte(ret), uint8(ret>>8))
}

func UnsetSysProxy() {
	sysproxy, err := getSysProxy()
	if err != nil {
		log.Println(err)
		return
	}
	clearSysproxy := sysproxy.NewProc("ClearSystemProxy")
	ret, _, e1 := syscall.Syscall(clearSysproxy.Addr(), 0, 0, 0, 0)
	if ret == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Printf("%d.%d", byte(ret), uint8(ret>>8))
}

/*
 * from https://github.com/golang/sys/blob/master/windows/zsyscall_windows.go#L1073
 */
// Do the interface allocations only once for common
// Errno values.
const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

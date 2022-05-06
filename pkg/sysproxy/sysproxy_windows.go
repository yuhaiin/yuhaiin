package sysproxy

import (
	_ "embed"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"
)

// use github.com/Asutorufa/winproxy/c to generate dll
/*
	gcc -c proxy.c -o proxy.o
	gcc proxy.o -o proxy.dll -shared -lwininet
	ar cr libproxy.a proxy.o
*/

//go:embed proxy.dll
var proxyDLL []byte

func expertDLL(execPath string) (string, error) {
	dll := filepath.Join(filepath.Dir(execPath), "proxy.dll")

	_, err := os.Stat(dll)
	if err == nil {
		return dll, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stat %s error: %s", dll, err)
	}
	err = ioutil.WriteFile(dll, proxyDLL, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("write %s failed: %w", dll, err)
	}
	return dll, nil
}

func strPtr(s string) (uintptr, error) {
	b, err := syscall.BytePtrFromString(s)
	if err != nil {
		return 0, err
	}
	return uintptr(unsafe.Pointer(b)), nil
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

func getdll() (*syscall.LazyDLL, error) {
	execPath, err := getExecPath()
	if err != nil {
		return nil, err
	}

	dll, err := expertDLL(execPath)
	if err != nil {
		return nil, fmt.Errorf("expertDLL failed: %w", err)
	}
	log.Println("System Proxy DLL:", dll)
	return syscall.NewLazyDLL(dll), nil
}

func SetSysProxy(http, _ string) {
	if err := setSysProxy(http, ""); err != nil {
		log.Println("SetSysProxy failed:", err)
	}
}

func setSysProxy(http, _ string) error {
	if http == "" {
		return nil
	}
	d, err := getdll()
	if err != nil {
		return fmt.Errorf("getSysProxy failed: %w", err)
	}
	sw := d.NewProc("switch_system_proxy")
	if err := sw.Find(); err != nil {
		return fmt.Errorf("can't find switch_system_proxy: %w", err)
	}
	r1, _, err := sw.Call(1)
	log.Println(r1, "switch_system_proxy:", err)

	setserver := d.NewProc("set_system_proxy_server")
	if err := setserver.Find(); err != nil {
		return fmt.Errorf("can't find set_system_proxy_server: %w", err)
	}
	host, err := strPtr(http)
	if err != nil {
		return fmt.Errorf("can't convert host: %w", err)
	}
	r1, _, err = setserver.Call(host)
	log.Println(r1, "set_system_proxy_server:", err)

	setbypass := d.NewProc("set_system_proxy_bypass_list")
	if err := setbypass.Find(); err != nil {
		return fmt.Errorf("can't find set_system_proxy_bypass_list: %w", err)
	}
	bypass, err := strPtr("localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;172.32.*;192.168.*")
	if err != nil {
		return fmt.Errorf("can't convert bypasslist to ptr: %w", err)
	}
	r1, _, err = setbypass.Call(bypass)
	log.Println(r1, "set_system_proxy_bypass_list:", err)
	return nil
}

func UnsetSysProxy() {
	if err := unsetSysProxy(); err != nil {
		log.Println("UnsetSysProxy failed:", err)
	}
}

func unsetSysProxy() error {
	d, err := getdll()
	if err != nil {
		return fmt.Errorf("getSysProxy failed: %w", err)
	}
	sw := d.NewProc("switch_system_proxy")
	if err := sw.Find(); err != nil {
		return fmt.Errorf("can't find switch_system_proxy: %w", err)
	}
	r1, _, err := sw.Call(0)
	log.Println(r1, "switch_system_proxy:", err)
	return nil
}

/*
 * check error from https://github.com/golang/sys/blob/master/windows/zsyscall_windows.go#L1073
 */

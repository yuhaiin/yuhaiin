package sysproxy

import (
	_ "embed"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log"
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
	dll := filepath.Join(execPath, "proxy.dll")

	_, err := os.Stat(dll)
	if err == nil {
		return dll, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stat %s error: %w", dll, err)
	}

	err = os.WriteFile(dll, proxyDLL, os.ModePerm)
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

func getdll(path string) (*syscall.LazyDLL, error) {
	dll, err := expertDLL(path)
	if err != nil {
		return nil, fmt.Errorf("expertDLL failed: %w", err)
	}
	log.Info("use windows proxy dll file", "dll", dll)
	return syscall.NewLazyDLL(dll), nil
}

func SetSysProxy(path, hh, hp, _, _ string) {
	if err := setSysProxy(path, net.JoinHostPort(hh, hp), ""); err != nil {
		log.Error("set system proxy failed:", "err", err)
	}
}

func setSysProxy(path, http, _ string) error {
	if http == "" {
		return nil
	}
	d, err := getdll(path)
	if err != nil {
		return fmt.Errorf("get proxy dll failed: %w", err)
	}
	sw := d.NewProc("switch_system_proxy")
	if err := sw.Find(); err != nil {
		return fmt.Errorf("can't find switch_system_proxy: %w", err)
	}
	r1, _, err := sw.Call(1)
	log.Debug("switch_system_proxy:", "r1", r1, "err", err)

	setserver := d.NewProc("set_system_proxy_server")
	if err := setserver.Find(); err != nil {
		return fmt.Errorf("can't find set_system_proxy_server: %w", err)
	}
	host, err := strPtr(http)
	if err != nil {
		return fmt.Errorf("can't convert host: %w", err)
	}
	r1, _, err = setserver.Call(host)
	log.Debug("set_system_proxy_server:", "r1", r1, "err", err)

	setbypass := d.NewProc("set_system_proxy_bypass_list")
	if err := setbypass.Find(); err != nil {
		return fmt.Errorf("can't find set_system_proxy_bypass_list: %w", err)
	}

	bypass, err := strPtr("localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;172.32.*;192.168.*")
	if err != nil {
		return fmt.Errorf("can't convert bypasslist to ptr: %w", err)
	}
	r1, _, err = setbypass.Call(bypass)
	log.Debug("set_system_proxy_bypass_list:", "r1", r1, "err", err)
	return nil
}

func UnsetSysProxy(path string) {
	if err := unsetSysProxy(path); err != nil {
		log.Error("unset wystem proxy failed:", "err", err)
	}
}

func unsetSysProxy(path string) error {
	d, err := getdll(path)
	if err != nil {
		return fmt.Errorf("get proxy dll failed: %w", err)
	}
	sw := d.NewProc("switch_system_proxy")
	if err := sw.Find(); err != nil {
		return fmt.Errorf("can't find switch_system_proxy: %w", err)
	}
	r1, _, err := sw.Call(0)
	log.Debug("switch_system_proxy:", "r1", r1, "err", err)
	return nil
}

/*
 * check error from https://github.com/golang/sys/blob/master/windows/zsyscall_windows.go#L1073
 */

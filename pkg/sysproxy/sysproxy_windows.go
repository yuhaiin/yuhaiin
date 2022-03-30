package sysproxy

import (
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
)

//go:embed dll_windows/Release/*
var sysproxyDLL embed.FS

func expertDLL(execPath string) (string, error) {
	var arch string
	if runtime.GOARCH == "amd64" {
		arch = "x64"
	} else if runtime.GOARCH == "386" {
		arch = "x86"
	} else {
		return "", errors.New("not support " + runtime.GOARCH)
	}

	dllDir := path.Join(filepath.Dir(execPath), "static", "dll", arch)
	dll := filepath.Join(dllDir, "sysproxydll.dll")

	_, err := os.Stat(dll)
	if err == nil {
		return dll, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stat %s error: %s", dllDir, err)
	}

	err = os.MkdirAll(dllDir, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("mkdir %s error: %s", dllDir, err)
	}
	f, err := fs.Sub(sysproxyDLL, "dll_windows")
	if err != nil {
		return "", err
	}
	if f, err = fs.Sub(f, "Release"); err != nil {
		return "", err
	}
	if f, err = fs.Sub(f, arch); err != nil {
		return "", err
	}
	ff, err := f.Open("sysproxydll.dll")
	if err != nil {
		return "", err
	}
	defer ff.Close()

	of, err := os.OpenFile(dll, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return "", fmt.Errorf("open %s error: %s", dll, err)
	}
	defer of.Close()

	_, err = io.Copy(of, ff)
	if err != nil {
		return "", fmt.Errorf("copy %s error: %s", dll, err)
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

func getSysProxy() (*syscall.LazyDLL, error) {
	execPath, err := getExecPath()
	if err != nil {
		return nil, err
	}

	dll, err := expertDLL(execPath)
	if err != nil {
		return nil, fmt.Errorf("expertDLL failed: %w", err)
	}
	logasfmt.Println("System Proxy DLL:", dll)
	return syscall.NewLazyDLL(dll), nil
}

func SetSysProxy(http, _ string) {
	if http == "" {
		return
	}
	httpHostname, httpPort, err := net.SplitHostPort(http)
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
	if err = setSysProxy.Find(); err != nil {
		logasfmt.Println("can't find SetSystemProxy func", err)
		return
	}

	hostPtr, err := strPtr(httpHostname)
	if err != nil {
		log.Println(err)
		return
	}
	portPtr, err := strPtr(httpPort)
	if err != nil {
		log.Println(err)
		return
	}
	emptyPtr, err := strPtr("")
	if err != nil {
		log.Println(err)
		return
	}
	ret, _, e1 := syscall.Syscall(setSysProxy.Addr(), 3, hostPtr, portPtr, emptyPtr)
	if ret == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	if err != nil {
		log.Println(err)
		return
	}
	logasfmt.Printf("%d.%d\n", byte(ret), uint8(ret>>8))
}

func UnsetSysProxy() {
	sysproxy, err := getSysProxy()
	if err != nil {
		log.Println(err)
		return
	}
	clearSysproxy := sysproxy.NewProc("ClearSystemProxy")
	if err = clearSysproxy.Find(); err != nil {
		logasfmt.Println("can't find ClearSystemProxy func", err)
		return
	}
	ret, _, e1 := syscall.Syscall(clearSysproxy.Addr(), 0, 0, 0, 0)
	if ret == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	if err != nil {
		log.Println(err)
		return
	}
	logasfmt.Printf("%d.%d\n", byte(ret), uint8(ret>>8))
}

/*
 * check error from https://github.com/golang/sys/blob/master/windows/zsyscall_windows.go#L1073
 */

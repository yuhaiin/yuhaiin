package sysproxy

import (
	_ "embed"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/memmod"
)

// use github.com/Asutorufa/winproxy/c to generate dll
/*
	gcc -c proxy.c -o proxy.o
	gcc proxy.o -o proxy.dll -shared -lwininet
	ar cr libproxy.a proxy.o
*/

//go:embed proxy.dll
var proxyDLL []byte

func SetSysProxy(hh, hp, _, _ string) {
	if hh == "" && hp == "" {
		return
	}

	if err := setSysProxy(net.JoinHostPort(hh, hp), ""); err != nil {
		log.Error("set system proxy failed:", "err", err)
	}
}

var (
	dll               = memmod.NewLazyDLL("proxy.dll", proxyDLL)
	switchSystemProxy = dll.NewProc("switch_system_proxy")
	setSystemProxy    = dll.NewProc("set_system_proxy_server")
	setSystemBypass   = dll.NewProc("set_system_proxy_bypass_list")
)

func setSysProxy(http, _ string) error {
	if http == "" {
		return nil
	}

	r1, _, errno := switchSystemProxy.Call(1)
	log.Debug("switch_system_proxy:", "r1", r1, "err", errno)

	host, err := memmod.StrPtr(http)
	if err != nil {
		return fmt.Errorf("can't convert host: %w", err)
	}
	r1, _, err = setSystemProxy.Call(host)
	log.Debug("set_system_proxy_server:", "r1", r1, "err", err)

	bypass, err := memmod.StrPtr("localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;172.32.*;192.168.*")
	if err != nil {
		return fmt.Errorf("can't convert bypasslist to ptr: %w", err)
	}
	r1, _, err = setSystemBypass.Call(bypass)
	log.Debug("set_system_proxy_bypass_list:", "r1", r1, "err", err)

	return nil
}

func UnsetSysProxy() {
	if err := unsetSysProxy(); err != nil {
		log.Error("unset wystem proxy failed:", "err", err)
	}
}

func unsetSysProxy() error {
	r1, _, err := switchSystemProxy.Call(0)
	log.Debug("switch_system_proxy:", "r1", r1, "err", err)
	return nil
}

/*
 * check error from https://github.com/golang/sys/blob/master/windows/zsyscall_windows.go#L1073
 */

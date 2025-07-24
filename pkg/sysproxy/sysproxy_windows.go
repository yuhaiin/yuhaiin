package sysproxy

import (
	"errors"
	"fmt"
	"math/big"
	"net"
	"slices"
	"strings"
	"syscall"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

func SetSysProxy(hh, hp, _, _ string) {
	if hh == "" && hp == "" {
		return
	}

	if err := setSysProxy(net.JoinHostPort(hh, hp), ""); err != nil {
		log.Error("set system proxy failed:", "err", err)
	}
}

func setSysProxy(http, _ string) error {
	if http == "" {
		return nil
	}

	return SetGlobalProxy(http,
		"localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;172.32.*;192.168.*")
}

func UnsetSysProxy() {
	if err := Off(); err != nil {
		log.Error("unset wystem proxy failed:", "err", err)
	}
}

// copy from github.com/Trisia/gosysproxy

var (
	wininet, _           = syscall.LoadLibrary("Wininet.dll")
	internetSetOption, _ = syscall.GetProcAddress(wininet, "InternetSetOptionW")
	// https://learn.microsoft.com/zh-cn/windows/win32/api/wininet/nf-wininet-internetqueryoptionw
	internetQueryOption, _ = syscall.GetProcAddress(wininet, "InternetQueryOptionA")
)

const (
	_INTERNET_OPTION_PER_CONNECTION_OPTION  = 75
	_INTERNET_OPTION_PROXY_SETTINGS_CHANGED = 95
	_INTERNET_OPTION_REFRESH                = 37
	_INTERNET_OPTION_PROXY                  = 38
)

const (
	_PROXY_TYPE_DIRECT         = 0x00000001 // direct to net
	_PROXY_TYPE_PROXY          = 0x00000002 // via named proxy
	_PROXY_TYPE_AUTO_PROXY_URL = 0x00000004 // autoproxy URL
	_PROXY_TYPE_AUTO_DETECT    = 0x00000008 // use autoproxy detection
)

const (
	_INTERNET_PER_CONN_FLAGS                        = 1
	_INTERNET_PER_CONN_PROXY_SERVER                 = 2
	_INTERNET_PER_CONN_PROXY_BYPASS                 = 3
	_INTERNET_PER_CONN_AUTOCONFIG_URL               = 4
	_INTERNET_PER_CONN_AUTODISCOVERY_FLAGS          = 5
	_INTERNET_PER_CONN_AUTOCONFIG_SECONDARY_URL     = 6
	_INTERNET_PER_CONN_AUTOCONFIG_RELOAD_DELAY_MINS = 7
	_INTERNET_PER_CONN_AUTOCONFIG_LAST_DETECT_TIME  = 8
	_INTERNET_PER_CONN_AUTOCONFIG_LAST_DETECT_URL   = 9
	_INTERNET_PER_CONN_FLAGS_UI                     = 10
)

const (
	INTERNET_OPEN_TYPE_PRECONFIG = 0 // use registry configuration
	INTERNET_OPEN_TYPE_DIRECT    = 1
	INTERNET_OPEN_TYPE_PROXY     = 3
)

type internetPerConnOptionList struct {
	dwSize        uint32
	pszConnection *uint16
	dwOptionCount uint32
	dwOptionError uint32
	pOptions      uintptr
}

type internetPreConnOption struct {
	dwOption uint32
	value    uint64
}

// internetProxyInfo https://learn.microsoft.com/zh-cn/windows/win32/api/wininet/ns-wininet-internet_proxy_info
type internetProxyInfo struct {
	dwAccessType    uint32
	lpszProxy       *uint16
	lpszProxyBypass *uint16
}

type ProxyStatus struct {
	// - 0: INTERNET_OPEN_TYPE_PRECONFIG: use registry configuration
	// - 1: INTERNET_OPEN_TYPE_DIRECT: direct to net
	// - 3: INTERNET_OPEN_TYPE_PROXY:  via named proxy
	Type  uint32
	Proxy string // IP:Port，eg: "127.0.0.1:7890"
	// eg: ["localhost","127.*"]，
	Bypass               []string
	DisableProxyIntranet bool
}

func stringPtrAddr(str string) (uint64, error) {
	scriptLocPtr, err := syscall.UTF16PtrFromString(str)
	if err != nil {
		return 0, err
	}
	n := new(big.Int)
	n.SetString(fmt.Sprintf("%x\n", scriptLocPtr), 16)
	return n.Uint64(), nil
}

func newParam(n int) internetPerConnOptionList {
	return internetPerConnOptionList{
		dwSize:        4,
		pszConnection: nil,
		dwOptionCount: uint32(n),
		dwOptionError: 0,
		pOptions:      0,
	}
}

func SetPAC(scriptLoc string) error {
	if scriptLoc == "" {
		return errors.New("script is empty")
	}

	scriptLocAddr, err := stringPtrAddr(scriptLoc)
	if err != nil {
		return err
	}

	param := newParam(2)
	options := []internetPreConnOption{
		{dwOption: _INTERNET_PER_CONN_FLAGS, value: _PROXY_TYPE_AUTO_PROXY_URL | _PROXY_TYPE_DIRECT},
		{dwOption: _INTERNET_PER_CONN_AUTOCONFIG_URL, value: scriptLocAddr},
	}
	param.pOptions = uintptr(unsafe.Pointer(&options[0]))
	ret, _, infoPtr := syscall.SyscallN(internetSetOption,
		4,
		0,
		_INTERNET_OPTION_PER_CONNECTION_OPTION,
		uintptr(unsafe.Pointer(&param)),
		unsafe.Sizeof(param),
		0, 0)
	if ret != 1 {
		return infoPtr
	}

	return Flush()
}

func SetGlobalProxy(proxyServer string, bypass string) error {
	if proxyServer == "" {
		return errors.New("proxy is empty")
	}

	proxyServerPtrAddr, err := stringPtrAddr(proxyServer)
	if err != nil {
		return err
	}

	if bypass == "" {
		bypass = "<local>"
	}

	bypassAddr, err := stringPtrAddr(bypass)
	if err != nil {
		return err
	}

	param := newParam(3)
	options := []internetPreConnOption{
		{dwOption: _INTERNET_PER_CONN_FLAGS, value: _PROXY_TYPE_PROXY | _PROXY_TYPE_DIRECT},
		{dwOption: _INTERNET_PER_CONN_PROXY_SERVER, value: proxyServerPtrAddr},
		{dwOption: _INTERNET_PER_CONN_PROXY_BYPASS, value: bypassAddr},
	}
	param.pOptions = uintptr(unsafe.Pointer(&options[0]))
	ret, _, infoPtr := syscall.SyscallN(internetSetOption,
		4,
		0,
		_INTERNET_OPTION_PER_CONNECTION_OPTION,
		uintptr(unsafe.Pointer(&param)),
		unsafe.Sizeof(param),
		0, 0)
	if ret != 1 {
		return fmt.Errorf(">> Ret [%d] Setting options: %w", ret, infoPtr)
	}

	return Flush()
}

func Off() error {
	param := newParam(1)
	option := internetPreConnOption{
		dwOption: _INTERNET_PER_CONN_FLAGS,
		//value:    _PROXY_TYPE_AUTO_DETECT | _PROXY_TYPE_DIRECT}
		value: _PROXY_TYPE_DIRECT}
	param.pOptions = uintptr(unsafe.Pointer(&option))
	ret, _, infoPtr := syscall.SyscallN(internetSetOption,
		4,
		0,
		_INTERNET_OPTION_PER_CONNECTION_OPTION,
		uintptr(unsafe.Pointer(&param)),
		unsafe.Sizeof(param),
		0, 0)
	if ret != 1 {
		return fmt.Errorf(">> Ret [%d] Setting options: %w", ret, infoPtr)
	}
	return Flush()
}

func Flush() error {
	ret, _, infoPtr := syscall.SyscallN(internetSetOption,
		4,
		0,
		_INTERNET_OPTION_PROXY_SETTINGS_CHANGED,
		0, 0,
		0, 0)
	if ret != 1 {
		return fmt.Errorf(">> Ret [%d] Setting options: %w", ret, infoPtr)
	}

	ret, _, infoPtr = syscall.SyscallN(internetSetOption,
		4,
		0,
		_INTERNET_OPTION_REFRESH,
		0, 0,
		0, 0)
	if ret != 1 {
		return fmt.Errorf(">> Ret [%d] Setting options: %w", ret, infoPtr)
	}
	return nil
}

func Status() (*ProxyStatus, error) {
	var bufferLength uint32 = 1024 * 10
	buffer := make([]byte, bufferLength)
	ret, _, infoPtr := syscall.SyscallN(internetQueryOption,
		4,
		0,
		_INTERNET_OPTION_PROXY,
		uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&bufferLength)),
		0, 0)
	if ret != 1 {
		return nil, fmt.Errorf(">> Ret [%d] Setting options: %w", ret, infoPtr)
	}
	//fmt.Println(hex.Dump(buffer[:bufferLength]))
	proxyInfo := (*internetProxyInfo)(unsafe.Pointer(&buffer[0]))
	bypassArr := asciiPtrToString(proxyInfo.lpszProxyBypass)

	res := &ProxyStatus{
		Type:   proxyInfo.dwAccessType,
		Proxy:  asciiPtrToString(proxyInfo.lpszProxy),
		Bypass: strings.Split(bypassArr, " "),
	}
	res.DisableProxyIntranet = slices.Contains(res.Bypass, "<local>")
	return res, nil
}

func asciiPtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	res := []byte{}
	end := unsafe.Pointer(p)
	for {
		if *(*uint8)(end) == 0 {
			break
		}
		res = append(res, *(*uint8)(end))
		end = unsafe.Pointer(uintptr(end) + 1)
	}
	return string(res)
}

package getdelay

import (
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"../config/config"
	"./httpserver"
	"./socks5Server"
	// "../socks5ToHttp"
)

// StartHTTP <--
func StartHTTP(configPath string) {
	argument := config.GetConfig(configPath)
	socks5ToHTTP := &httpserver.Socks5ToHTTP{
		HTTPServer:   "",
		HTTPPort:     "",
		Socks5Server: argument["localAddress"],
		Socks5Port:   argument["localPort"],
		ByPass:       false,
		ToHTTP:       true,
	}
	if argument["localPort"] == "" {
		socks5ToHTTP.Socks5Port = "1080"
	}
	httpProxy := strings.Split(argument["httpProxy"], ":")
	socks5ToHTTP.HTTPServer = httpProxy[0]
	socks5ToHTTP.HTTPPort = httpProxy[1]
	if err := socks5ToHTTP.HTTPProxy(); err != nil {
		log.Println(err)
	}
}

func GetHttpProxyCmd() (*exec.Cmd, error) {
	executablePath, err := os.Executable()
	if err != nil {
		log.Println(err)
		return &exec.Cmd{}, err
	}
	// log.Println(executablePath)

	return exec.Command(executablePath, "-sd", "http"), nil
}

// StartHTTP <--
func StartHTTPBypass(configPath string) {
	argument := config.GetConfig(configPath)
	socks5ToHTTP := &httpserver.Socks5ToHTTP{
		ToHTTP:            true,
		HTTPServer:        "",
		HTTPPort:          "",
		Socks5Server:      argument["localAddress"],
		Socks5Port:        argument["localPort"],
		ByPass:            true,
		CidrFile:          argument["cidrFile"],
		DNSServer:         argument["dnsServer"],
		KeepAliveTimeout:  15 * time.Second,
		Timeout:           10 * time.Second,
		UseLocalResolveIp: true,
	}

	if argument["localPort"] == "" {
		socks5ToHTTP.Socks5Port = "1080"
	}
	httpProxy := strings.Split(argument["httpProxy"], ":")
	socks5ToHTTP.HTTPServer = httpProxy[0]
	socks5ToHTTP.HTTPPort = httpProxy[1]
	log.Println(httpProxy)
	if err := socks5ToHTTP.HTTPProxy(); err != nil {
		log.Println(err)
	}
}

// StartHTTP <--
func StartSocks5Bypass(configPath string) {
	argument := config.GetConfig(configPath)
	socks5S := socks5server.ServerSocks5{
		Server:         "",
		Port:           "",
		Bypass:         true,
		CidrFile:       argument["cidrFile"],
		ToShadowsocksr: true,
		Socks5Server:   argument["localAddress"],
		Socks5Port:     argument["localPort"],
		//208.67.222.222#5353
		//208.67.222.220#5353
		//58.132.8.1 beijing edu DNS server
		//101.6.6.6 beijing tsinghua dns server
		DNSServer:         argument["dnsServer"],
		KeepAliveTimeout:  15 * time.Second,
		Timeout:           10 * time.Second,
		UseLocalResolveIp: true,
	}
	if argument["localPort"] == "" {
		socks5S.Socks5Port = "1080"
	}
	socks5BypassProxy := strings.Split(argument["socks5WithBypassAddressAndPort"], ":")
	socks5S.Server = socks5BypassProxy[0]
	socks5S.Port = socks5BypassProxy[1]
	if err := socks5S.Socks5(); err != nil {
		log.Println(err)
		return
	}
}

func GetHttpProxyBypassCmd() (*exec.Cmd, error) {
	executablePath, err := os.Executable()
	if err != nil {
		log.Println(err)
		return &exec.Cmd{}, err
	}
	// log.Println(executablePath)

	return exec.Command(executablePath, "-sd", "httpBp"), nil
}

func GetSocks5ProxyBypassCmd() (*exec.Cmd, error) {
	executablePath, err := os.Executable()
	if err != nil {
		log.Println(err)
		return &exec.Cmd{}, err
	}
	// log.Println(executablePath)

	return exec.Command(executablePath, "-sd", "socks5Bp"), nil
}

// StartHTTPByArgumentB <--
// func StartHTTPByArgumentB() {
// 	executablePath, err := os.Executable()
// 	if err != nil {
// 		log.Println(err)
// 		return
// 	}
// 	// log.Println(executablePath)
// 	first, err := os.StartProcess(executablePath, []string{executablePath, "-d", "httpB"}, &os.ProcAttr{
// 		Sys: &syscall.SysProcAttr{
// 			Setsid: true,
// 		},
// 	})
// 	if err != nil {
// 		log.Println(err)
// 		return
// 	}
// 	log.Println(first.Pid)
// 	first.Wait()
// }

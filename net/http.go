package getdelay

import (
	"log"
	"os"
	"os/exec"
	"strings"

	"../config/config"
	"./socks5ToHttp"
	// "../socks5ToHttp"
)

// StartHTTP <--
func StartHTTP(configPath string) {
	argument := config.GetConfig(configPath)
	socks5ToHTTP := &socks5ToHttp.Socks5ToHTTP{
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

func GetHttpProxyCmd(configPath string) (*exec.Cmd, error) {
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
	socks5ToHTTP := &socks5ToHttp.Socks5ToHTTP{
		ToHTTP:       true,
		HTTPServer:   "",
		HTTPPort:     "",
		Socks5Server: argument["localAddress"],
		Socks5Port:   argument["localPort"],
		ByPass:       true,
		CidrFile:     argument["cidrFile"],
		DNSServer:    argument["dnsServer"],
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

func GetHttpProxyBypassCmd(configPath string) (*exec.Cmd, error) {
	executablePath, err := os.Executable()
	if err != nil {
		log.Println(err)
		return &exec.Cmd{}, err
	}
	// log.Println(executablePath)

	return exec.Command(executablePath, "-sd", "httpBp"), nil
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

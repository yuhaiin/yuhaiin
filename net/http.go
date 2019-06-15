package getdelay

import (
	"log"
	"os"
	"syscall"

	"../config"
	"./socks5ToHttp"
	// "../socks5ToHttp"
)

// StartHTTP <--
func StartHTTP(configPath string) {
	argument := config.GetConfig(configPath)
	socks5ToHTTP := &socks5ToHttp.Socks5ToHTTP{
		HTTPServer:   "",
		HTTPPort:     "8081",
		Socks5Server: argument["localAddress"],
		Socks5Port:   argument["localPort"],
	}
	if argument["localPort"] == "" {
		socks5ToHTTP.Socks5Port = "1080"
	}
	if err := socks5ToHTTP.HTTPProxy(); err != nil {
		log.Println(err)
	}
}

// StartHTTPByArgument <--
func StartHTTPByArgument() {
	executablePath, err := os.Executable()
	if err != nil {
		log.Println(err)
		return
	}
	// log.Println(executablePath)
	first, err := os.StartProcess(executablePath, []string{executablePath, "-http"}, &os.ProcAttr{
		Sys: &syscall.SysProcAttr{
			Setsid: true,
		},
	})
	if err != nil {
		log.Println(err)
		return
	}
	log.Println(first.Pid)
	// first.Wait()
}

// StartHTTPByArgumentB <--
func StartHTTPByArgumentB() {
	executablePath, err := os.Executable()
	if err != nil {
		log.Println(err)
		return
	}
	// log.Println(executablePath)
	first, err := os.StartProcess(executablePath, []string{executablePath, "-httpB"}, &os.ProcAttr{
		Sys: &syscall.SysProcAttr{
			Setsid: true,
		},
	})
	if err != nil {
		log.Println(err)
		return
	}
	log.Println(first.Pid)
	first.Wait()
}

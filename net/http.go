package getdelay

import (
	"log"
	"strings"

	"../config"
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

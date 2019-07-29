package main

import (
	"log"

	socks5server "./socks5Server"
	// "./socks5ToHttp"
)

func main() {
	// httpS := socks5ToHttp.Socks5ToHTTP{
	// 	ToHTTP:       true,
	// 	HTTPServer:   "127.0.0.1",
	// 	HTTPPort:     "8188",
	// 	Socks5Server: "127.0.0.1",
	// 	Socks5Port:   "1080",
	// 	CidrFile:     "/run/media/asutorufa/D/code/golang/cn_rules.conf",
	// }
	// if err := httpS.HTTPProxy(); err != nil {
	// 	log.Println(err)
	// 	return
	// }

	socks5S := socks5server.ServerSocks5{
		Server:         "127.0.0.1",
		Port:           "1083",
		Bypass:         true,
		CidrFile:       "/mnt/share/code/golang/cn_rules.conf",
		ToShadowsocksr: true,
		Socks5Server:   "127.0.0.1",
		Socks5Port:     "1080",
	}
	if err := socks5S.Socks5(); err != nil {
		log.Println(err)
		return
	}
}

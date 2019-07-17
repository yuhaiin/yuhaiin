package main

import (
	"log"

	"./socks5ToHttp"
)

func main() {
	httpS := socks5ToHttp.Socks5ToHTTP{
		ToHTTP:       true,
		HTTPServer:   "127.0.0.1",
		HTTPPort:     "8188",
		Socks5Server: "127.0.0.1",
		Socks5Port:   "1080",
		CidrFile:     "/home/asutorufa/Downloads/badvpn-master/badvpn-build/bad-vpn/bin/cn_rules.conf",
	}
	if err := httpS.HTTPProxy(); err != nil {
		log.Println(err)
		return
	}
}

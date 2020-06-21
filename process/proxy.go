package process

import (
	"log"

	httpserver "github.com/Asutorufa/yuhaiin/net/proxy/http/server"
	socks5server "github.com/Asutorufa/yuhaiin/net/proxy/socks5/server"
)

var (
	Socks5, _ = socks5server.NewSocks5Server(conFig.Socks5ProxyAddress, "", "")
	HttpS, _  = httpserver.NewHTTPServer(conFig.HttpProxyAddress, "", "")
)

func UpdateListen() (err error) {
	err = Socks5.UpdateListen(conFig.Socks5ProxyAddress)
	if err != nil {
		log.Println(err)
	}
	err = HttpS.UpdateListenHost(conFig.HttpProxyAddress)
	if err != nil {
		log.Println(err)
	}

	return extendsUpdateListen(conFig)
}

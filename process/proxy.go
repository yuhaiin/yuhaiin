package process

import (
	"log"

	"github.com/Asutorufa/yuhaiin/config"
	httpserver "github.com/Asutorufa/yuhaiin/net/proxy/http/server"
	"github.com/Asutorufa/yuhaiin/net/proxy/redir/redirserver"
	socks5server "github.com/Asutorufa/yuhaiin/net/proxy/socks5/server"
)

var (
	Socks5 *socks5server.Server
	HttpS  *httpserver.Server
	Redir  *redirserver.Server
)

func proxyInit() {
	conFig, err := config.SettingDecodeJSON()
	if err != nil {
		log.Print(err)
		return
	}
	Socks5, _ = socks5server.NewSocks5Server(conFig.Socks5ProxyAddress, "", "")
	HttpS, _ = httpserver.NewHTTPServer(conFig.HttpProxyAddress, "", "")
	extendsProxyInit(conFig)
}

func UpdateListen() (err error) {
	conFig, err := config.SettingDecodeJSON()
	if err != nil {
		return err
	}

	_ = Socks5.UpdateListen(conFig.Socks5ProxyAddress)
	_ = HttpS.UpdateListenHost(conFig.HttpProxyAddress)

	return extendsUpdateListen(conFig)
}

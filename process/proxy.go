package process

import (
	"github.com/Asutorufa/yuhaiin/config"
	httpserver "github.com/Asutorufa/yuhaiin/net/proxy/http/server"
	socks5server "github.com/Asutorufa/yuhaiin/net/proxy/socks5/server"
)

var (
	Socks5, _ = socks5server.NewSocks5Server(conFig.Socks5ProxyAddress, "", "")
	HttpS, _  = httpserver.NewHTTPServer(conFig.HttpProxyAddress, "", "")
)

func UpdateListen() (err error) {
	conFig, err := config.SettingDecodeJSON()
	if err != nil {
		return err
	}

	_ = Socks5.UpdateListen(conFig.Socks5ProxyAddress)
	_ = HttpS.UpdateListenHost(conFig.HttpProxyAddress)

	return extendsUpdateListen(conFig)
}

package process

import (
	"log"
	"net/url"

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

	if conFig.Socks5ProxyAddress != "" {
		socks5Addr, err := url.Parse("//" + conFig.Socks5ProxyAddress)
		if err != nil {
			log.Println(err)
		}

		Socks5, err = socks5server.NewSocks5Server(socks5Addr.Hostname(), socks5Addr.Port(), "", "")
		if err != nil {
			log.Print(err)
			return
		}
	}

	if conFig.HttpProxyAddress != "" {
		httpAddr, err := url.Parse("//" + conFig.HttpProxyAddress)
		if err != nil {
			log.Print(err)
			return
		}

		HttpS, err = httpserver.NewHTTPServer(httpAddr.Hostname(), httpAddr.Port(), "", "")
		if err != nil {
			log.Print(err)
			return
		}
	}

	extendsProxyInit(conFig)
}

func UpdateListen() (err error) {
	conFig, err := config.SettingDecodeJSON()
	if err != nil {
		return err
	}

	if Socks5.GetListenHost() != conFig.Socks5ProxyAddress {
		socks5Addr, err := url.Parse("//" + conFig.Socks5ProxyAddress)
		if err != nil {
			return err
		}

		err = Socks5.UpdateListen(socks5Addr.Hostname(), socks5Addr.Port())
		if err != nil {
			return err
		}
	}

	if HttpS.GetListenHost() != conFig.HttpProxyAddress {
		httpAddr, err := url.Parse("//" + conFig.HttpProxyAddress)
		if err != nil {
			return err
		}

		err = HttpS.UpdateListenHost(httpAddr.Hostname(), httpAddr.Port())
		if err != nil {
			return err
		}
	}
	return extendsUpdateListen(conFig)
}

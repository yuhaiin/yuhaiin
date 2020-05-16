package process

import (
	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/net/proxy/http/server"
	"github.com/Asutorufa/yuhaiin/net/proxy/redir/redirserver"
	"github.com/Asutorufa/yuhaiin/net/proxy/socks5/server"
	"log"
	"net/url"
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
		if Socks5, err = socks5server.NewSocks5Server(socks5Addr.Hostname(), socks5Addr.Port(), "", ""); err != nil {
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
		if HttpS, err = httpserver.NewHTTPServer(httpAddr.Hostname(), httpAddr.Port(), "", ""); err != nil {
			log.Print(err)
			return
		}
	}

	if conFig.RedirProxyAddress != "" {
		redirAddr, err := url.Parse("//" + conFig.RedirProxyAddress)
		if err != nil {
			log.Print(err)
			return
		}
		if Redir, err = redirserver.NewRedir(redirAddr.Hostname(), redirAddr.Port()); err != nil {
			log.Print(err)
			return
		}
	}
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
		if err = Socks5.UpdateListen(socks5Addr.Hostname(), socks5Addr.Port()); err != nil {
			return err
		}
	}

	if HttpS.GetListenHost() != conFig.HttpProxyAddress {
		httpAddr, err := url.Parse("//" + conFig.HttpProxyAddress)
		if err != nil {
			return err
		}
		if err = HttpS.UpdateListenHost(httpAddr.Hostname(), httpAddr.Port()); err != nil {
			return err
		}
	}

	if Redir.GetHost() != conFig.RedirProxyAddress {
		redirAddr, err := url.Parse("//" + conFig.RedirProxyAddress)
		if err != nil {
			return err
		}
		if Redir, err = redirserver.NewRedir(redirAddr.Hostname(), redirAddr.Port()); err != nil {
			return err
		}
	}
	return nil
}

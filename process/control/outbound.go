package ServerControl

import (
	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/net/proxy/http/server"
	"github.com/Asutorufa/yuhaiin/net/proxy/socks5/server"
	"log"
	"net"
	"net/url"
)

type OutBound struct {
	Socks5 *socks5server.Server
	HttpS  *httpserver.Server
}

func NewOutBound() (*OutBound, error) {
	o := &OutBound{}
	conFig, err := config.SettingDecodeJSON()
	if err != nil {
		return nil, err
	}
	socks5, err := url.Parse("//" + conFig.Socks5ProxyAddress)
	if err != nil {
		log.Println(err)
	}
	if o.Socks5, err = socks5server.NewSocks5Server(socks5.Hostname(), socks5.Port(), "", "", nil); err != nil {
		return nil, err
	}

	http, err := url.Parse("//" + conFig.HttpProxyAddress)
	if err != nil {
		return nil, err
	}
	if o.HttpS, err = httpserver.NewHTTPServer(http.Hostname(), http.Port(), "", "", nil); err != nil {
		return nil, err
	}
	return o, nil
}

func (o *OutBound) changeForwardConn(conn func(host string) (net.Conn, error)) {
	o.Socks5.ForwardFunc = conn
	o.HttpS.ForwardFunc = conn
}

func (o *OutBound) UpdateListenerAddress() error {
	conFig, err := config.SettingDecodeJSON()
	if err != nil {
		return err
	}
	socks5, err := url.Parse("//" + conFig.Socks5ProxyAddress)
	if err != nil {
		log.Println(err)
	}
	o.Socks5.Server, o.Socks5.Port = socks5.Hostname(), socks5.Port()

	http, err := url.Parse("//" + conFig.HttpProxyAddress)
	if err != nil {
		return err
	}
	o.HttpS.Server, o.HttpS.Port = http.Hostname(), http.Port()
	return nil
}

func (o *OutBound) Stop() error {
	if err := o.HttpS.Close(); err != nil {
		return err
	}
	if err := o.Socks5.Close(); err != nil {
		return err
	}
	return nil
}

func (o *OutBound) Start() {
	go func() {
		if err := o.Socks5.Socks5(); err != nil {
			log.Println(err)
			return
		}
	}()

	go func() {
		if err := o.HttpS.HTTPProxy(); err != nil {
			log.Println(err)
			return
		}
	}()
}

func (o *OutBound) Restart() {
	if err := o.Stop(); err != nil {
		log.Println(err)
	} else {
		o.Start()
	}
}

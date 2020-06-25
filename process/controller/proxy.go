package controller

import (
	"github.com/Asutorufa/yuhaiin/net/proxy/interfaces"

	httpserver "github.com/Asutorufa/yuhaiin/net/proxy/http/server"
	socks5server "github.com/Asutorufa/yuhaiin/net/proxy/socks5/server"
)

//var (
//	Socks5 interfaces.Server
//	HttpS  interfaces.Server
//	Redir  interfaces.Server
//)

type LocalListen struct {
	Socks5 interfaces.Server
	HttpS  interfaces.Server
	Redir  interfaces.Server
}

func NewLocalListenController() *LocalListen {
	return &LocalListen{}
}

func (l *LocalListen) SetSocks5Host(host string) (err error) {
	if l.Socks5 == nil {
		l.Socks5, err = socks5server.NewSocks5Server(host, "", "")
		return
	}
	return l.Socks5.UpdateListen(host)
}

func (l *LocalListen) SetHTTPHost(host string) (err error) {
	if l.HttpS == nil {
		l.HttpS, err = httpserver.NewHTTPServer(host, "", "")
		return
	}
	return l.HttpS.UpdateListen(host)
}

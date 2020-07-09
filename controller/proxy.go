package controller

import (
	"fmt"

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

type Hosts struct {
	Socks5 string
	HTTP   string
	Redir  string
}

type LocalListenOption func(hosts *Hosts)

func NewLocalListenCon(option LocalListenOption) (l *LocalListen, erra error) {
	l = &LocalListen{}

	if option == nil {
		return l, nil
	}

	hosts := &Hosts{}
	option(hosts)
	// Local HTTP Server Host
	err := l.SetHTTPHost(hosts.HTTP)
	if err != nil {
		erra = fmt.Errorf("UpdateHTTPListenErr -> %v", err)
	}

	// Local Socks5 Server Host
	err = l.SetSocks5Host(hosts.Socks5)
	if err != nil {
		erra = fmt.Errorf("UpdateSOCKS5ListenErr -> %v", err)
	}

	// Linux/Darwin Redir Server Host
	err = l.SetRedirHost(hosts.Redir)
	if err != nil {
		erra = fmt.Errorf("UpdateRedirListenErr -> %v", err)
	}

	return
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

func (l *LocalListen) SetAllHost(option LocalListenOption) (erra error) {
	if option == nil {
		return
	}
	hosts := &Hosts{}
	option(hosts)
	// Local HTTP Server Host
	err := l.SetHTTPHost(hosts.HTTP)
	if err != nil {
		erra = fmt.Errorf("UpdateHTTPListenErr -> %v", err)
	}

	// Local Socks5 Server Host
	err =
		l.SetSocks5Host(hosts.Socks5)
	if err != nil {
		erra = fmt.Errorf("UpdateSOCKS5ListenErr -> %v", err)
	}

	// Linux/Darwin Redir Server Host
	err = l.SetRedirHost(hosts.Redir)
	if err != nil {
		erra = fmt.Errorf("UpdateRedirListenErr -> %v", err)
	}

	return
}

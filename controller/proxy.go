package controller

import (
	"fmt"
	"log"
	"net"
	"time"

	httpserver "github.com/Asutorufa/yuhaiin/net/proxy/http/server"
	proxyI "github.com/Asutorufa/yuhaiin/net/proxy/interface"
	"github.com/Asutorufa/yuhaiin/net/proxy/redir/redirserver"
	socks5server "github.com/Asutorufa/yuhaiin/net/proxy/socks5/server"
)

type sType int

var (
	hTTP   sType = 1
	socks5 sType = 2
	redir  sType = 3
	arrTCP       = []sType{hTTP, socks5, redir}
	arrUDP       = []sType{socks5}
)

type LocalListen struct {
	Server    map[sType]proxyI.Server
	UDPServer map[sType]proxyI.Server
	hosts     *Hosts
}

type Hosts struct {
	Socks5  string
	HTTP    string
	Redir   string
	TCPConn func(string) (net.Conn, error)
}

type LocalListenOption func(hosts *Hosts)

func NewLocalListenCon(option LocalListenOption) (l *LocalListen, err error) {
	l = &LocalListen{
		Server:    map[sType]proxyI.Server{},
		UDPServer: map[sType]proxyI.Server{},
	}

	if option == nil {
		return l, nil
	}
	hosts := &Hosts{
		TCPConn: func(s string) (net.Conn, error) {
			return net.DialTimeout("tcp", s, 5*time.Second)
		},
	}
	option(hosts)
	l.hosts = hosts

	for index := range arrTCP {
		l.Server[arrTCP[index]] = l.newTCP(hosts, arrTCP[index])
	}
	for index := range arrUDP {
		l.UDPServer[arrUDP[index]] = l.newUDP(hosts, arrUDP[index])
	}

	l.setTCPConn(hosts.TCPConn)
	return
}

func (l *LocalListen) SetAHost(option LocalListenOption) (erra error) {
	if option == nil {
		return nil
	}
	option(l.hosts)
	for index := range arrTCP {
		if l.Server[arrTCP[index]] == nil {
			l.Server[arrTCP[index]] = l.newTCP(l.hosts, arrTCP[index])
			continue
		}
		err := l.Server[arrTCP[index]].UpdateListen(l.getHost(l.hosts, arrTCP[index]))
		if err != nil {
			erra = fmt.Errorf("%v\n UpdateListen %d -> %v", erra, arrTCP[index], err)
		}
	}

	for index := range arrUDP {
		if l.UDPServer[arrUDP[index]] == nil {
			continue
		}
		err := l.Server[arrUDP[index]].UpdateListen(l.getHost(l.hosts, arrUDP[index]))
		if err != nil {
			erra = fmt.Errorf("%v\n UpdateListen %d -> %v", erra, arrUDP[index], err)
		}
	}
	l.setTCPConn(l.hosts.TCPConn)
	return
}

func (l *LocalListen) setTCPConn(conn func(string) (net.Conn, error)) {
	if conn == nil {
		return
	}
	for index := range arrTCP {
		if l.Server[arrTCP[index]] == nil {
			continue
		}
		switch l.Server[arrTCP[index]].(type) {
		case proxyI.TCPServer:
			l.Server[arrTCP[index]].(proxyI.TCPServer).SetTCPConn(conn)
		}
	}
}

func (l *LocalListen) newTCP(host *Hosts, sType2 sType) proxyI.Server {
	if host == nil {
		return nil
	}
	switch sType2 {
	case hTTP:
		server, err := proxyI.NewTCPServer(host.HTTP, httpserver.HTTPHandle())
		if err != nil {
			log.Printf("httpserver New -> %v", err)
			return nil
		}
		return server
	case socks5:
		server, err := proxyI.NewTCPServer(host.Socks5, socks5server.Socks5Handle())
		if err != nil {
			log.Printf("socks5server New -> %v", err)
			return nil
		}
		return server
	case redir:
		server, err := proxyI.NewTCPServer(host.Redir, redirserver.RedirHandle())
		if err != nil {
			log.Printf("redirserver New -> %v", err)
			return nil
		}
		return server
	}
	return nil
}

func (l *LocalListen) newUDP(hosts *Hosts, sType2 sType) proxyI.Server {
	if hosts == nil {
		return nil
	}
	switch sType2 {
	case socks5:
		server, err := proxyI.NewUDPServer(hosts.Socks5, socks5server.Socks5UDPHandle())
		if err != nil {
			return nil
		}
		return server
	}
	return nil
}

func (l *LocalListen) getHost(option *Hosts, sType2 sType) string {
	if option == nil {
		return ""
	}
	switch sType2 {
	case hTTP:
		return option.HTTP
	case socks5:
		return option.Socks5
	case redir:
		return option.Redir
	}
	return ""
}

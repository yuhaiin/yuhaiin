package controller

import (
	"fmt"
	"log"
	"net"
	"time"
	"runtime"

	httpserver "github.com/Asutorufa/yuhaiin/net/proxy/http/server"
	proxyI "github.com/Asutorufa/yuhaiin/net/proxy/interface"
	"github.com/Asutorufa/yuhaiin/net/proxy/redir/redirserver"
	socks5server "github.com/Asutorufa/yuhaiin/net/proxy/socks5/server"
)

type sType int

const (
	hTTP sType = 1 << iota
	socks5
	redir
	udp
)

var (
	support = []sType{hTTP, socks5, socks5 | udp, redir}
	ref     = map[sType]func(string) (proxyI.Server, error){
		hTTP: func(host string) (proxyI.Server, error) {
			return proxyI.NewTCPServer(host, httpserver.HTTPHandle())
		},
		socks5: func(host string) (proxyI.Server, error) {
			return proxyI.NewTCPServer(host, socks5server.Socks5Handle())
		},
		redir: func(host string) (proxyI.Server, error) {
			if runtime.GOOS == "windows"{
				return nil,fmt.Errorf("Redir not support windows")
			}
			return proxyI.NewTCPServer(host, redirserver.RedirHandle())
		},
		socks5 | udp: func(s string) (proxyI.Server, error) {
			return proxyI.NewUDPServer(s, socks5server.Socks5UDPHandle())
		},
	}
)

type LocalListen struct {
	Server map[sType]proxyI.Server
	hosts  *llOpt
}

// llOpt Local listener opts
type llOpt struct {
	hosts   map[sType]string
	tcpConn func(string) (net.Conn, error)
}

// LlOption Local Listener Option
type LlOption func(hosts *llOpt)

func WithSocks5(host string) LlOption {
	return func(hosts *llOpt) {
		hosts.hosts[socks5] = host
		hosts.hosts[socks5|udp] = host
	}
}

func WithRedir(host string) LlOption {
	return func(hosts *llOpt) {
		hosts.hosts[redir] = host
	}
}

func WithHTTP(host string) LlOption {
	return func(hosts *llOpt) {
		hosts.hosts[hTTP] = host
	}
}

func WithTCPConn(f func(string) (net.Conn, error)) LlOption {
	return func(opt *llOpt) {
		opt.tcpConn = f
	}
}

func NewLocalListenCon(opt ...LlOption) (l *LocalListen, err error) {
	hosts := &llOpt{
		tcpConn: func(s string) (net.Conn, error) {
			return net.DialTimeout("tcp", s, 5*time.Second)
		},
		hosts: map[sType]string{},
	}
	for index := range opt {
		if opt[index] == nil {
			continue
		}
		opt[index](hosts)
	}

	l = &LocalListen{
		Server: map[sType]proxyI.Server{},
		hosts:  hosts,
	}

	for _, typE := range support {
		if ref[typE] == nil {
			log.Printf("can't find %d function\n", typE)
			continue
		}
		l.Server[typE], err = ref[typE](hosts.hosts[typE])
		if err != nil {
			log.Println(err)
			continue
		}
	}

	l.setTCPConn(hosts.tcpConn)
	return l,nil
}

func (l *LocalListen) SetAHost(opt ...LlOption) (erra error) {
	if opt == nil {
		return nil
	}
	var err error

	for index := range opt {
		if opt[index] == nil {
			continue
		}
		opt[index](l.hosts)
	}
	for _, typE := range support {
		if l.Server[typE] == nil {
			if ref[typE] == nil {
				continue
			}
			l.Server[typE], err = ref[typE](l.hosts.hosts[typE])
			if err != nil {
				log.Println(err)
			}
			continue
		}
		err := l.Server[typE].UpdateListen(l.hosts.hosts[typE])
		if err != nil {
			erra = fmt.Errorf("%v\n UpdateListen %d -> %v", erra, typE, err)
		}
	}
	l.setTCPConn(l.hosts.tcpConn)
	return
}

func (l *LocalListen) setTCPConn(conn func(string) (net.Conn, error)) {
	if conn == nil {
		return
	}
	fmt.Println("Local Listener Set TCP Proxy", &conn)
	for _, typE := range support {
		if l.Server[typE] == nil {
			continue
		}
		switch l.Server[typE].(type) {
		case proxyI.TCPServer:
			l.Server[typE].(proxyI.TCPServer).SetTCPConn(conn)
		}
	}
}

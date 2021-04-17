package app

import (
	"fmt"
	"log"
	"runtime"

	httpserver "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/redirserver"
	socks5server "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
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
	ref     = map[sType]func(string) (proxy.Server, error){
		hTTP: func(host string) (proxy.Server, error) {
			return proxy.NewTCPServer(host, httpserver.HTTPHandle())
		},
		socks5: func(host string) (proxy.Server, error) {
			return proxy.NewTCPServer(host, socks5server.Socks5Handle())
		},
		redir: func(host string) (proxy.Server, error) {
			if runtime.GOOS == "windows" {
				log.Println("redir not support windows")
				return nil, nil
			}
			return proxy.NewTCPServer(host, redirserver.RedirHandle())
		},
		socks5 | udp: func(s string) (proxy.Server, error) {
			return proxy.NewUDPServer(s, socks5server.Socks5UDPHandle())
		},
	}
)

type LocalListen struct {
	Server map[sType]proxy.Server
	hosts  *llOpt
}

// llOpt Local listener opts
type llOpt struct {
	hosts map[sType]string
	proxy proxy.Proxy
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

func WithProxy(p proxy.Proxy) LlOption {
	return func(opt *llOpt) {
		opt.proxy = p
	}
}

func NewLocalListenCon(opt ...LlOption) (l *LocalListen, err error) {
	hosts := &llOpt{
		proxy: &proxy.DefaultProxy{},
		hosts: map[sType]string{},
	}
	for i := range opt {
		if opt[i] == nil {
			continue
		}
		opt[i](hosts)
	}

	l = &LocalListen{
		Server: map[sType]proxy.Server{},
		hosts:  hosts,
	}

	for _, style := range support {
		if ref[style] == nil {
			log.Printf("can't find %d function\n", style)
			continue
		}

		l.Server[style], err = ref[style](hosts.hosts[style])
		if err != nil {
			log.Println(err)
		}
	}

	l.setConn()
	return l, nil
}

func (l *LocalListen) SetAHost(opt ...LlOption) (erra error) {
	if len(opt) == 0 {
		return nil
	}

	for i := range opt {
		if opt[i] == nil {
			continue
		}
		opt[i](l.hosts)
	}

	var err error
	for _, style := range support {
		if l.Server[style] == nil && ref[style] == nil {
			continue
		}

		if l.Server[style] == nil {
			l.Server[style], err = ref[style](l.hosts.hosts[style])
		} else {
			err = l.Server[style].UpdateListen(l.hosts.hosts[style])
		}

		if err != nil {
			erra = fmt.Errorf("%v\n UpdateListen %d -> %v", erra, style, err)
		}
	}
	l.setConn()
	return
}

func (l *LocalListen) setConn() {
	for _, style := range support {
		l.Server[style].SetProxy(l.hosts.proxy)
	}
}

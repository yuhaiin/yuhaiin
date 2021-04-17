package app

import (
	"fmt"
	"runtime"

	"github.com/Asutorufa/yuhaiin/internal/config"
	httpserver "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	redirserver "github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/server"
	socks5server "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
)

type Listener struct {
	socks5 proxy.Server
	http   proxy.Server
	redir  proxy.Server
	hosts  *config.Proxy
	proxy  proxy.Proxy
}

func NewListener(c *config.Proxy, pro proxy.Proxy) (l *Listener, err error) {
	l = &Listener{
		proxy: pro,
		hosts: c,
	}

	l.socks5, err = socks5server.NewServer(l.hosts.Socks5, "", "")
	if err != nil {
		return nil, fmt.Errorf("create socks5 server failed: %v", err)
	}
	l.http, err = httpserver.NewServer(l.hosts.HTTP, "", "")
	if err != nil {
		return nil, fmt.Errorf("create http server failed: %v", err)
	}

	if runtime.GOOS != "windows" {
		l.redir, err = redirserver.NewServer(l.hosts.Redir)
		if err != nil {
			return nil, fmt.Errorf("create redir server failed: %v", err)
		}
	}

	l.SetProxy(l.proxy)
	return l, nil
}

func (l *Listener) SetServer(c *config.Proxy) {
	l.http.SetServer(l.hosts.GetHTTP())
	l.socks5.SetServer(l.hosts.GetSocks5())
	if runtime.GOOS != "windows" {
		l.redir.SetServer(l.hosts.GetRedir())
	}
}

func (l *Listener) SetProxy(p proxy.Proxy) {
	if p == nil {
		l.proxy = &proxy.DefaultProxy{}
	} else {
		l.proxy = p
	}

	l.socks5.SetProxy(l.proxy)
	l.http.SetProxy(l.proxy)
	if runtime.GOOS != "windows" {
		l.redir.SetProxy(l.proxy)
	}
}

package app

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/internal/config"
	hs "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	rs "github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/server"
	ss "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
)

type Listener struct {
	socks5 proxy.Server
	http   proxy.Server
	redir  proxy.Server
	proxy.Proxy
}

func NewListener(c *config.Config, pro proxy.Proxy) (l *Listener, err error) {
	if pro == nil {
		pro = &proxy.DefaultProxy{}
	}
	l = &Listener{Proxy: pro}

	// err = c.Exec(func(s *config.Setting) error {
	// 	l.socks5, err = ss.NewServer(s.Proxy.Socks5, "", "")
	// 	if err != nil {
	// 		return fmt.Errorf("create socks5 server failed: %v", err)
	// 	}

	// 	l.http, err = hs.NewServer(s.Proxy.HTTP, "", "")
	// 	if err != nil {
	// 		return fmt.Errorf("create http server failed: %v", err)
	// 	}
	// 	l.redir, err = rs.NewServer(s.Proxy.Redir)
	// 	if err != nil {
	// 		return fmt.Errorf("create redir server failed: %v", err)
	// 	}
	// 	return nil
	// })
	// if err != nil {
	// 	return nil, err
	// }

	var errors []error
	c.AddObserverAndExec(func(current, old *config.Setting) bool {
		return true
	}, func(current *config.Setting) {
		var err error
		if l.http != nil {
			l.http.SetServer(current.Proxy.HTTP)
		} else {
			l.http, err = hs.NewServer(current.Proxy.HTTP, "", "")
			if err != nil {
				errors = append(errors, err)
			}
		}

		if l.socks5 != nil {
			l.socks5.SetServer(current.Proxy.Socks5)
		} else {
			l.socks5, err = ss.NewServer(current.Proxy.Socks5, "", "")
			if err != nil {
				errors = append(errors, err)
			}
		}

		if l.redir != nil {
			l.redir.SetServer(current.Proxy.Redir)
		} else {
			l.redir, err = rs.NewServer(current.Proxy.Redir)
			if err != nil {
				errors = append(errors, err)
			}
		}
	})
	if errors != nil {
		fmt.Println(errors)
	}

	// c.AddObserver(func(cc, _ *config.Setting) {
	// 	l.http.SetServer(cc.Proxy.GetHTTP())
	// 	l.socks5.SetServer(cc.Proxy.GetSocks5())
	// 	l.redir.SetServer(cc.Proxy.GetRedir())
	// })

	l.socks5.SetProxy(l)
	l.http.SetProxy(l)
	l.redir.SetProxy(l)

	return l, nil
}

func (l *Listener) SetProxy(p proxy.Proxy) {
	if p == nil {
		l.Proxy = &proxy.DefaultProxy{}
	} else {
		l.Proxy = p
	}
}

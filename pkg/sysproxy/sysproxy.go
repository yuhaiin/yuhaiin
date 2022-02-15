package sysproxy

import "github.com/Asutorufa/yuhaiin/internal/config"

func Set(conf *config.Config) {
	conf.AddObserverAndExec(func(current, old *config.Setting) bool {
		return current.SystemProxy.HTTP != old.SystemProxy.HTTP ||
			current.SystemProxy.Socks5 != old.SystemProxy.Socks5 ||
			current.Proxy.HTTP != old.Proxy.HTTP ||
			current.Proxy.Socks5 != old.Proxy.Socks5
	}, func(s *config.Setting) {
		UnsetSysProxy()
		var http, socks5 string
		if s.SystemProxy.HTTP {
			http = s.Proxy.HTTP
		}
		if s.SystemProxy.Socks5 {
			socks5 = s.Proxy.Socks5
		}
		SetSysProxy(http, socks5)
	})
}

func Unset() {
	UnsetSysProxy()
}

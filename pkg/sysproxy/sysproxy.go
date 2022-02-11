package sysproxy

import "github.com/Asutorufa/yuhaiin/internal/config"

func Set(conf *config.Config) {
	setSysProxy := func(s *config.Setting) {
		var http, socks5 string
		if s.SystemProxy.HTTP {
			http = s.Proxy.HTTP
		}
		if s.SystemProxy.Socks5 {
			socks5 = s.Proxy.Socks5
		}
		SetSysProxy(http, socks5)
	}

	conf.Exec(func(s *config.Setting) error {
		setSysProxy(s)
		return nil
	})
	conf.AddObserver(func(current, old *config.Setting) {
		if current.SystemProxy.HTTP != old.SystemProxy.HTTP ||
			current.SystemProxy.Socks5 != old.SystemProxy.Socks5 ||
			current.Proxy.HTTP != old.Proxy.HTTP ||
			current.Proxy.Socks5 != old.Proxy.Socks5 {
			UnsetSysProxy()
			setSysProxy(current)
		}
	})
}

func Unset() {
	UnsetSysProxy()
}

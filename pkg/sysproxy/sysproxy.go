package sysproxy

import (
	"github.com/Asutorufa/yuhaiin/internal/config"

	"google.golang.org/protobuf/proto"
)

func Set(conf *config.Config) {
	conf.AddObserverAndExec(func(current, old *config.Setting) bool {
		return proto.Equal(current.Proxy, old.Proxy)
	}, func(s *config.Setting) {
		UnsetSysProxy()
		var http, socks5 string
		if s.SystemProxy.HTTP {
			http = s.Proxy.Proxy[config.Proxy_http.String()]
		}
		if s.SystemProxy.Socks5 {
			socks5 = s.Proxy.Proxy[config.Proxy_socks5.String()]
		}
		SetSysProxy(http, socks5)
	})
}

func Unset() {
	UnsetSysProxy()
}

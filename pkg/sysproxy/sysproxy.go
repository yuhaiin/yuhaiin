package sysproxy

import (
	"github.com/Asutorufa/yuhaiin/internal/config"
	cb "github.com/Asutorufa/yuhaiin/pkg/protos/config"

	"google.golang.org/protobuf/proto"
)

func Set(conf *config.Config) {
	conf.AddObserverAndExec(func(current, old *cb.Setting) bool {
		return proto.Equal(current.Server, old.Server)
	}, func(s *cb.Setting) {
		UnsetSysProxy()
		var http, socks5 string

		for _, v := range s.Server.Servers {
			if v.GetHttp() != nil && s.SystemProxy.Http {
				http = v.GetHttp().GetHost()
			}

			if v.GetSocks5() != nil && s.SystemProxy.Socks5 {
				socks5 = v.GetSocks5().GetHost()
			}
		}
		SetSysProxy(http, socks5)
	})
}

func Unset() {
	UnsetSysProxy()
}

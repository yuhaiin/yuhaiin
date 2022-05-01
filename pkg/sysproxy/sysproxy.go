package sysproxy

import (
	cb "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/proto"
)

var server *cb.Server

func Update(s *cb.Setting) {
	if proto.Equal(server, s.Server) {
		return
	}
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
	server = s.Server
}

func Unset() {
	UnsetSysProxy()
}

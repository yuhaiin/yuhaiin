package sysproxy

import (
	"net"
	"net/netip"
	"strconv"

	cb "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"google.golang.org/protobuf/proto"
)

var server *listener.Config

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

	SetSysProxy(replaceUnspecified(http), replaceUnspecified(socks5))
	server = s.Server
}

func replaceUnspecified(s string) string {
	if ip, err := netip.ParseAddrPort(s); err == nil {
		if ip.Addr().IsUnspecified() {
			if ip.Addr().Is6() {
				return net.JoinHostPort(net.IPv6loopback.String(), strconv.Itoa(int(ip.Port())))
			} else {
				return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(ip.Port())))

			}
		}
	}

	return s
}

func Unset() {
	UnsetSysProxy()
}

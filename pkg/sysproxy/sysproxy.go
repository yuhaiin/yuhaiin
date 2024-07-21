package sysproxy

import (
	"net"
	"net/netip"
	"strconv"

	cb "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"google.golang.org/protobuf/proto"
)

var server *listener.InboundConfig
var system *cb.SystemProxy

func Update() func(s *cb.Setting) {
	return func(s *cb.Setting) {
		if proto.Equal(server, s.Server) &&
			proto.Equal(system, s.SystemProxy) {
			return
		}

		UnsetSysProxy()
		var http, socks5 string

		for _, v := range s.Server.Inbounds {
			if s.SystemProxy.Http && http == "" {
				if v.GetEnabled() && v.GetTcpudp() != nil {
					if v.GetHttp() != nil || v.GetMix() != nil {
						http = v.GetTcpudp().GetHost()
					}
				}
			}

			if s.SystemProxy.Socks5 && socks5 == "" {
				if v.GetEnabled() && v.GetTcpudp() != nil {
					if v.GetSocks5() != nil || v.GetMix() != nil {
						http = v.GetTcpudp().GetHost()
					}
				}
			}

			if (!s.SystemProxy.Socks5 || (s.SystemProxy.Socks5 && socks5 != "")) &&
				(!s.SystemProxy.Http || (s.SystemProxy.Http && http != "")) {
				break
			}
		}

		hh, hp := replaceUnspecified(http)
		sh, sp := replaceUnspecified(socks5)

		SetSysProxy(hh, hp, sh, sp)
		server = s.Server
		system = s.SystemProxy
	}
}

func replaceUnspecified(s string) (string, string) {
	if s == "" {
		return "", ""
	}
	host, port, err := net.SplitHostPort(s)
	if err == nil && host == "" {
		return "127.0.0.1", port
	}

	if ip, err := netip.ParseAddrPort(s); err == nil {
		if ip.Addr().IsUnspecified() {
			if ip.Addr().Is6() {
				return net.IPv6loopback.String(), strconv.Itoa(int(ip.Port()))
			} else {
				return "127.0.0.1", strconv.Itoa(int(ip.Port()))
			}
		}
	}

	return host, port
}

func Unset() {
	UnsetSysProxy()
}

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

func Update(path string) func(s *cb.Setting) {
	return func(s *cb.Setting) {
		if proto.Equal(server, s.Server) {
			return
		}
		UnsetSysProxy(path)
		var http, socks5 string

		for _, v := range s.Server.Servers {
			if s.SystemProxy.Http && http == "" {
				if v.GetEnabled() && v.GetHttp() != nil {
					http = v.GetHttp().GetHost()
				}

				if v.GetEnabled() && v.GetMix() != nil {
					http = v.GetMix().GetHost()
				}
			}

			if s.SystemProxy.Socks5 && socks5 == "" {
				if v.GetEnabled() && v.GetSocks5() != nil {
					socks5 = v.GetSocks5().GetHost()
				}

				if v.GetEnabled() && v.GetMix() != nil {
					socks5 = v.GetMix().GetHost()
				}
			}

			if (s.SystemProxy.Socks5 && socks5 != "") && (s.SystemProxy.Http && http != "") {
				break
			}
		}

		hh, hp := replaceUnspecified(http)
		sh, sp := replaceUnspecified(socks5)
		SetSysProxy(path, hh, hp, sh, sp)
		server = s.Server
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

func Unset(path string) {
	UnsetSysProxy(path)
}

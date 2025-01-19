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
		if proto.Equal(server, s.GetServer()) &&
			proto.Equal(system, s.GetSystemProxy()) {
			return
		}

		UnsetSysProxy()
		var http, socks5 string

		for _, v := range s.GetServer().GetInbounds() {
			if s.GetSystemProxy().GetHttp() && http == "" {
				if v.GetEnabled() && v.GetTcpudp() != nil {
					if v.GetHttp() != nil || v.GetMix() != nil {
						http = v.GetTcpudp().GetHost()
					}
				}
			}

			if s.GetSystemProxy().GetSocks5() && socks5 == "" {
				if v.GetEnabled() && v.GetTcpudp() != nil {
					if v.GetSocks5() != nil || v.GetMix() != nil {
						http = v.GetTcpudp().GetHost()
					}
				}
			}

			if (!s.GetSystemProxy().GetSocks5() || (s.GetSystemProxy().GetSocks5() && socks5 != "")) &&
				(!s.GetSystemProxy().GetHttp() || (s.GetSystemProxy().GetHttp() && http != "")) {
				break
			}
		}

		hh, hp := replaceUnspecified(http)
		sh, sp := replaceUnspecified(socks5)

		SetSysProxy(hh, hp, sh, sp)
		server = s.GetServer()
		system = s.GetSystemProxy()
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

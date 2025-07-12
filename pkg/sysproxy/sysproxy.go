package sysproxy

import (
	"net"
	"net/netip"
	"strconv"

	cb "github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

type config struct {
	http   host
	socks5 host
}

type host struct {
	enabled bool
	host    string
}

func (h host) Ok() bool {
	return !h.enabled || h.host != ""
}

func (h host) Empty() bool {
	return h.enabled && h.host == ""
}

var cfg config

func Update(s *cb.Setting) {
	ncfg := config{
		http: host{
			enabled: s.GetSystemProxy().GetHttp(),
			host:    "",
		},
		socks5: host{
			enabled: s.GetSystemProxy().GetSocks5(),
			host:    "",
		},
	}

	for _, v := range s.GetServer().GetInbounds() {
		if !v.GetEnabled() || v.GetTcpudp() == nil {
			continue
		}

		if ncfg.http.Empty() && (v.GetHttp() != nil || v.GetMix() != nil) {
			ncfg.http.host = v.GetTcpudp().GetHost()
		}

		if ncfg.socks5.Empty() && (v.GetSocks5() != nil || v.GetMix() != nil) {
			ncfg.socks5.host = v.GetTcpudp().GetHost()
		}

		if ncfg.http.Ok() && ncfg.socks5.Ok() {
			break
		}
	}

	if cfg == ncfg {
		return
	}

	UnsetSysProxy()

	hh, hp := replaceUnspecified(ncfg.http.host)
	sh, sp := replaceUnspecified(ncfg.socks5.host)

	SetSysProxy(hh, hp, sh, sp)
	cfg = ncfg
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

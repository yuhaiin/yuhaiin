package sysproxy

import (
	"net"
	"net/netip"
	"strconv"
)

var cfg struct {
	http   string
	socks5 string
}

func Update(http, socks5 string) {
	ncfg := struct {
		http   string
		socks5 string
	}{
		http:   http,
		socks5: socks5,
	}

	if cfg == ncfg {
		return
	}

	cfg = ncfg

	UnsetSysProxy()

	hh, hp := replaceUnspecified(cfg.http)
	sh, sp := replaceUnspecified(cfg.socks5)

	SetSysProxy(hh, hp, sh, sp)
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

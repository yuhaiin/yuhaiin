package native

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Info is the negotiated network configuration. DNS and routes are information
// for the caller, never changes to the host operating system.
type Info struct {
	Prefixes    []netip.Prefix
	DNS         []string
	Routes      []string
	Gateway     string
	Cipher      string
	PeerID      uint32
	MTU         int
	Ping        time.Duration
	PingRestart time.Duration
}

func ParsePush(reply string, cfg Config) (Info, error) {
	p := Info{MTU: 1500}
	if strings.HasPrefix(reply, "AUTH_FAILED") {
		return p, ErrAuth
	}
	if !strings.HasPrefix(reply, "PUSH_REPLY,") {
		return p, errors.New("openvpn: expected PUSH_REPLY")
	}
	for item := range strings.SplitSeq(reply, ",") {
		f := strings.Fields(item)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "ifconfig":
			if len(f) != 3 {
				return p, errors.New("openvpn: malformed ifconfig")
			}
			ip, err := netip.ParseAddr(f[1])
			second := net.ParseIP(f[2]).To4()
			if err != nil || !ip.Is4() || !validIP(ip) || second == nil {
				return p, errors.New("openvpn: invalid ifconfig")
			}
			bits := 32 // net30/point-to-point peers need only a local host address.
			if second[0] == 255 {
				n, width := net.IPMask(second).Size()
				if width != 32 {
					return p, errors.New("openvpn: noncontiguous netmask")
				}
				bits = n
			}
			p.Prefixes = append(p.Prefixes, netip.PrefixFrom(ip, bits))
		case "ifconfig-ipv6":
			if len(f) != 3 {
				return p, errors.New("openvpn: malformed ifconfig-ipv6")
			}
			prefix, err := netip.ParsePrefix(f[1])
			if err != nil || !prefix.Addr().Is6() || prefix.Addr().Is4In6() || !validIP(prefix.Addr()) {
				return p, errors.New("openvpn: invalid IPv6 prefix")
			}
			p.Prefixes = append(p.Prefixes, prefix)
		case "peer-id":
			if len(f) != 2 {
				return p, errors.New("openvpn: malformed peer-id")
			}
			n, err := strconv.ParseUint(f[1], 10, 24)
			if err != nil {
				return p, errors.New("openvpn: invalid peer-id")
			}
			p.PeerID = uint32(n)
		case "cipher":
			if len(f) != 2 || !slices.Contains(cfg.DataCiphers, f[1]) {
				return p, errors.New("openvpn: server selected an unoffered cipher")
			}
			p.Cipher = f[1]
		case "tun-mtu":
			if len(f) != 2 {
				return p, errors.New("openvpn: malformed tun-mtu")
			}
			n, err := strconv.Atoi(f[1])
			if err != nil || n < 576 || n > 1500 {
				return p, errors.New("openvpn: invalid pushed MTU")
			}
			p.MTU = n
		case "ping", "ping-restart":
			if len(f) != 2 {
				return p, errors.New("openvpn: malformed keepalive")
			}
			n, err := strconv.ParseUint(f[1], 10, 32)
			if err != nil || n > 86400 {
				return p, errors.New("openvpn: invalid keepalive")
			}
			d := time.Duration(n) * time.Second
			if f[0] == "ping" {
				p.Ping = d
			} else {
				p.PingRestart = d
			}
		case "dhcp-option":
			if len(f) == 3 && (f[1] == "DNS" || f[1] == "DNS6") {
				if ip, err := netip.ParseAddr(f[2]); err != nil || !validIP(ip) {
					return p, errors.New("openvpn: invalid pushed DNS")
				}
				p.DNS = append(p.DNS, f[2])
			}
		case "route", "route-ipv6", "redirect-gateway":
			p.Routes = append(p.Routes, item)
		case "route-gateway":
			if len(f) == 2 {
				p.Gateway = f[1]
			}
		case "compress", "comp-lzo", "fragment":
			return p, fmt.Errorf("openvpn: unsupported pushed option %s", f[0])
		case "key-derivation":
			return p, errors.New("openvpn: unadvertised key derivation")
		case "push-continuation":
			return p, errors.New("openvpn: fragmented PUSH_REPLY unsupported")
		}
	}
	if len(p.Prefixes) == 0 {
		return p, errors.New("openvpn: server pushed no tunnel address")
	}
	if p.Cipher == "" {
		p.Cipher = cfg.DataCiphers[0]
	}
	if cfg.MTU != 0 {
		p.MTU = min(p.MTU, cfg.MTU)
	}
	for _, prefix := range p.Prefixes {
		if prefix.Addr().Is6() && p.MTU < 1280 {
			return p, errors.New("openvpn: IPv6 requires MTU >= 1280")
		}
	}
	return p, nil
}

func validIP(ip netip.Addr) bool { return ip.IsValid() && !ip.IsUnspecified() && !ip.IsMulticast() }

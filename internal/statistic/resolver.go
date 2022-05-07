package statistic

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/proto"
)

type remoteResolver struct {
	config *protoconfig.Dns
	dns    dns.DNS
	dialer proxy.Proxy
}

func newRemoteResolver(dialer proxy.Proxy) *remoteResolver {
	return &remoteResolver{dialer: dialer}
}

func (r *remoteResolver) IsProxy() bool {
	if r.config == nil {
		return false
	}

	return r.config.Proxy
}

func (r *remoteResolver) Update(c *protoconfig.Setting) {
	if proto.Equal(r.config, c.Dns.Remote) {
		return
	}

	r.config = c.Dns.Remote
	r.dns = getDNS(r.config, r.dialer)
}

func (r *remoteResolver) LookupIP(host string) ([]net.IP, error) {
	if r.dns == nil {
		return nil, fmt.Errorf("dns not initialized")
	}
	return r.dns.LookupIP(host)
}

var _ dns.DNS = (*localResolver)(nil)

type localResolver struct {
	config   *protoconfig.Dns
	dns      dns.DNS
	dialer   proxy.Proxy
	resolver *net.Resolver
}

func newLocalResolver(dialer proxy.Proxy) *localResolver {
	return &localResolver{dialer: dialer}
}

func (l *localResolver) Update(c *protoconfig.Setting) {
	if proto.Equal(l.config, c.Dns.Local) {
		return
	}

	l.config = c.Dns.Local
	l.dns = getDNS(l.config, l.dialer)
	l.resolver = l.dns.Resolver()
}

func (l *localResolver) LookupIP(host string) ([]net.IP, error) {
	if l.dns == nil {
		return net.DefaultResolver.LookupIP(context.TODO(), "ip", host)
	}

	return l.dns.LookupIP(host)
}

func (l *localResolver) Resolver() *net.Resolver {
	if l.resolver == nil {
		return net.DefaultResolver
	}
	return l.resolver
}

func getDNS(dc *protoconfig.Dns, proxy proxy.Proxy) dns.DNS {
	_, subnet, err := net.ParseCIDR(dc.Subnet)
	if err != nil {
		p := net.ParseIP(dc.Subnet)
		if p != nil { // no mask
			var mask net.IPMask
			if p.To4() == nil { // ipv6
				mask = net.IPMask{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}
			} else {
				mask = net.IPMask{255, 255, 255, 255}
			}

			subnet = &net.IPNet{IP: p, Mask: mask}
		}
	}

	switch dc.Type {
	case protoconfig.Dns_doh:
		return dns.NewDoH(dc.Host, subnet, proxy)
	case protoconfig.Dns_dot:
		return dns.NewDoT(dc.Host, subnet, proxy)
	case protoconfig.Dns_tcp:
		fallthrough
	case protoconfig.Dns_udp:
		fallthrough
	default:
		return dns.NewDNS(dc.Host, subnet, proxy)
	}
}

func getDnsConfig(dc *protoconfig.Dns) string {
	host := dc.Host
	if dc.Type == protoconfig.Dns_doh {
		i := strings.Index(host, "://")
		if i != -1 {
			host = host[i+3:] // remove http scheme
		}

		i = strings.IndexByte(host, '/')
		if i != -1 {
			host = host[:i] // remove doh path
		}
	}

	h, _, err := net.SplitHostPort(host)
	if err == nil {
		host = h
	}

	return host
}

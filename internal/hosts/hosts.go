package hosts

import (
	"errors"
	"net"

	"github.com/Asutorufa/yuhaiin/internal/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
	"golang.org/x/net/dns/dnsmessage"
)

type hosts struct {
	hosts    syncmap.SyncMap[string, proxy.Address]
	dialer   proxy.Proxy
	resolver proxy.ResolverProxy
}

func NewHosts(dialer proxy.Proxy, resolve proxy.ResolverProxy) proxy.DialerResolverProxy {
	return &hosts{dialer: dialer, resolver: resolve}
}
func (h *hosts) Update(c *config.Setting) {
	h.hosts = syncmap.SyncMap[string, proxy.Address]{}

	for k, v := range c.Dns.Hosts {
		_, _, e1 := net.SplitHostPort(k)
		_, _, e2 := net.SplitHostPort(v)

		if e1 == nil && e2 == nil {
			addr, err := proxy.ParseAddress("", v)
			if err == nil {
				h.hosts.Store(k, addr)
			}
		}

		if e1 != nil && e2 != nil {
			h.hosts.Store(k, proxy.ParseAddressSplit("", v, proxy.EmptyPort))
		}
	}
}

func (h *hosts) Conn(addr proxy.Address) (net.Conn, error) { return h.dialer.Conn(h.getAddr(addr)) }
func (h *hosts) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	c, err := h.dialer.PacketConn(h.getAddr(addr))
	if err != nil {
		return nil, err
	}
	return &resolver.WrapAddressPacketConn{PacketConn: c, ProcessAddress: h.getAddr}, nil
}

type hostsKey struct{}

func (hostsKey) String() string { return "Hosts" }

func (h *hosts) getAddr(addr proxy.Address) proxy.Address {
	z, ok := h.hosts.Load(addr.Hostname())
	if ok {
		addr.WithValue(hostsKey{}, addr.Hostname())
		return addr.OverrideHostname(z.Hostname())
	}

	z, ok = h.hosts.Load(addr.String())
	if ok {
		addr.WithValue(hostsKey{}, addr.String())
		addr = addr.OverrideHostname(z.Hostname())
		addr = addr.OverridePort(z.Port())
	}

	return addr
}

func (h *hosts) Resolver(addr proxy.Address) dns.DNS { return &hostsResolver{h, addr} }

type hostsResolver struct {
	hosts *hosts
	addr  proxy.Address
}

func (h *hostsResolver) LookupIP(domain string) ([]net.IP, error) {
	addr := h.hosts.getAddr(proxy.ParseAddressSplit("", domain, proxy.EmptyPort))
	if addr.Type() == proxy.IP {
		return []net.IP{yerror.Ignore(addr.IP())}, nil
	}

	return h.hosts.resolver.Resolver(addr).LookupIP(addr.Hostname())
}

func (h *hostsResolver) Record(domain string, t dnsmessage.Type) (dns.IPResponse, error) {
	addr := h.hosts.getAddr(proxy.ParseAddressSplit("", domain, proxy.EmptyPort))
	if addr.Type() == proxy.IP {
		if t == dnsmessage.TypeAAAA {
			return dns.NewIPResponse([]net.IP{yerror.Ignore(addr.IP()).To16()}, 600), nil
		}

		if t == dnsmessage.TypeA && yerror.Ignore(addr.IP()).To4() != nil {
			return dns.NewIPResponse([]net.IP{yerror.Ignore(addr.IP()).To4()}, 600), nil
		}
		return nil, errors.New("here not include ipv6 hosts")
	}

	return h.hosts.resolver.Resolver(addr).Record(addr.Hostname(), t)
}
func (h *hostsResolver) Do(b []byte) ([]byte, error) { return h.hosts.resolver.Resolver(h.addr).Do(b) }
func (h *hostsResolver) Close() error                { return nil }

package resolver

import (
	"errors"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
	"golang.org/x/net/dns/dnsmessage"
)

type Hosts struct {
	hosts    syncmap.SyncMap[string, proxy.Address]
	dialer   proxy.Proxy
	resolver dns.DNS
}

func NewHosts(dialer proxy.Proxy, resolver dns.DNS) *Hosts {
	return &Hosts{dialer: dialer, resolver: resolver}
}
func (h *Hosts) Update(c *config.Setting) {
	h.hosts = syncmap.SyncMap[string, proxy.Address]{}

	for k, v := range c.Dns.Hosts {
		_, _, e1 := net.SplitHostPort(k)
		_, _, e2 := net.SplitHostPort(v)

		if e1 == nil && e2 == nil {
			addr, err := proxy.ParseAddress(0, v)
			if err == nil {
				h.hosts.Store(k, addr)
			}
		}

		if e1 != nil && e2 != nil {
			h.hosts.Store(k, proxy.ParseAddressPort(0, v, proxy.EmptyPort))
		}
	}
}

func (h *Hosts) Conn(addr proxy.Address) (net.Conn, error) { return h.dialer.Conn(h.getAddr(addr)) }
func (h *Hosts) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	c, err := h.dialer.PacketConn(h.getAddr(addr))
	if err != nil {
		return nil, err
	}
	return &dispatchPacketConn{c, h.getAddr}, nil
}

type hostsKey struct{}

func (hostsKey) String() string { return "Hosts" }

func (h *Hosts) getAddr(addr proxy.Address) proxy.Address {
	if _, ok := addr.Value(hostsKey{}); ok {
		return addr
	}

	z, ok := h.hosts.Load(addr.Hostname())
	if ok {
		addr.WithValue(hostsKey{}, addr.Hostname())
		addr = addr.OverrideHostname(z.Hostname())
		addr.WithValue(proxy.CurrentKey{}, addr)
		return addr
	}

	z, ok = h.hosts.Load(addr.String())
	if ok {
		addr.WithValue(hostsKey{}, addr.String())
		addr = addr.OverrideHostname(z.Hostname()).OverridePort(z.Port())
		addr.WithValue(proxy.CurrentKey{}, addr)
	}

	return addr
}

func (h *Hosts) LookupIP(domain string) ([]net.IP, error) {
	addr := h.getAddr(proxy.ParseAddressPort(0, domain, proxy.EmptyPort))
	if addr.Type() == proxy.IP {
		return []net.IP{yerror.Ignore(addr.IP())}, nil
	}

	return h.resolver.LookupIP(addr.Hostname())
}

func (h *Hosts) Record(domain string, t dnsmessage.Type) (dns.IPRecord, error) {
	addr := h.getAddr(proxy.ParseAddressPort(0, domain, proxy.EmptyPort))
	if addr.Type() == proxy.IP {
		if t == dnsmessage.TypeAAAA {
			return dns.IPRecord{IPs: []net.IP{yerror.Ignore(addr.IP()).To16()}, TTL: 600}, nil
		}

		if t == dnsmessage.TypeA && yerror.Ignore(addr.IP()).To4() != nil {
			return dns.IPRecord{IPs: []net.IP{yerror.Ignore(addr.IP()).To4()}, TTL: 600}, nil
		}
		return dns.IPRecord{}, errors.New("here not include ipv6 hosts")
	}

	return h.resolver.Record(addr.Hostname(), t)
}
func (h *Hosts) Do(addr string, b []byte) ([]byte, error) { return h.resolver.Do(addr, b) }
func (h *Hosts) Close() error                             { return nil }

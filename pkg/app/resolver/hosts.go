package resolver

import (
	"context"
	"errors"
	"net"

	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
	"golang.org/x/net/dns/dnsmessage"
)

type Hosts struct {
	hosts    syncmap.SyncMap[string, proxy.Address]
	dialer   proxy.Proxy
	resolver proxy.Resolver
}

func NewHosts(dialer proxy.Proxy, resolver proxy.Resolver) *Hosts {
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

func (h *Hosts) Dispatch(ctx context.Context, addr proxy.Address) (proxy.Address, error) {
	haddr := h.dispatchAddr(ctx, addr)
	return h.dialer.Dispatch(ctx, haddr)
}

func (h *Hosts) Conn(ctx context.Context, addr proxy.Address) (net.Conn, error) {
	return h.dialer.Conn(ctx, h.dispatchAddr(ctx, addr))
}
func (h *Hosts) PacketConn(ctx context.Context, addr proxy.Address) (net.PacketConn, error) {
	c, err := h.dialer.PacketConn(ctx, h.dispatchAddr(ctx, addr))
	if err != nil {
		return nil, err
	}
	return &dispatchPacketConn{c, h.dispatchAddr}, nil
}

type hostsKey struct{}

func (hostsKey) String() string { return "Hosts" }

func (h *Hosts) dispatchAddr(ctx context.Context, addr proxy.Address) proxy.Address {
	z, ok := h.hosts.Load(addr.Hostname())
	if ok {
		proxy.StoreFromContext(ctx).
			Add(hostsKey{}, addr.Hostname()).
			Add(proxy.CurrentKey{}, addr)
		return addr.OverrideHostname(z.Hostname())
	}

	z, ok = h.hosts.Load(addr.String())
	if ok {
		store := proxy.StoreFromContext(ctx)
		store.Add(hostsKey{}, addr.String())
		addr = addr.OverrideHostname(z.Hostname()).OverridePort(z.Port())
		store.Add(proxy.CurrentKey{}, addr)
	}

	return addr
}

func (h *Hosts) LookupIP(ctx context.Context, domain string) ([]net.IP, error) {
	addr := h.dispatchAddr(ctx, proxy.ParseAddressPort(0, domain, proxy.EmptyPort))
	if addr.Type() == proxy.IP {
		return []net.IP{yerror.Ignore(addr.IP(ctx))}, nil
	}

	return h.resolver.LookupIP(ctx, addr.Hostname())
}

func (h *Hosts) Record(ctx context.Context, domain string, t dnsmessage.Type) ([]net.IP, uint32, error) {
	addr := h.dispatchAddr(ctx, proxy.ParseAddressPort(0, domain, proxy.EmptyPort))
	if addr.Type() == proxy.IP {
		if t == dnsmessage.TypeAAAA {
			return []net.IP{yerror.Ignore(addr.IP(ctx)).To16()}, 600, nil
		}

		if t == dnsmessage.TypeA && yerror.Ignore(addr.IP(ctx)).To4() != nil {
			return []net.IP{yerror.Ignore(addr.IP(ctx)).To4()}, 600, nil
		}
		return nil, 0, errors.New("here not include ipv6 hosts")
	}

	return h.resolver.Record(ctx, addr.Hostname(), t)
}
func (h *Hosts) Do(ctx context.Context, addr string, b []byte) ([]byte, error) {
	return h.resolver.Do(ctx, addr, b)
}
func (h *Hosts) Close() error { return nil }
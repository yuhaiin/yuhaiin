package resolver

import (
	"context"
	"net"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
	"golang.org/x/net/dns/dnsmessage"
)

type Hosts struct {
	hosts    syncmap.SyncMap[string, netapi.Address]
	dialer   netapi.Proxy
	resolver netapi.Resolver
}

func NewHosts(dialer netapi.Proxy, resolver netapi.Resolver) *Hosts {
	return &Hosts{dialer: dialer, resolver: resolver}
}

func (h *Hosts) Update(c *config.Setting) {
	h.hosts = syncmap.SyncMap[string, netapi.Address]{}

	for k, v := range c.Dns.Hosts {
		_, _, e1 := net.SplitHostPort(k)
		_, _, e2 := net.SplitHostPort(v)

		if e1 == nil && e2 == nil {
			addr, err := netapi.ParseAddress(0, v)
			if err == nil {
				h.hosts.Store(k, addr)
			}
		}

		if e1 != nil && e2 != nil {
			h.hosts.Store(k, netapi.ParseAddressPort(0, v, netapi.EmptyPort))
		}
	}
}

func (h *Hosts) Dispatch(ctx context.Context, addr netapi.Address) (netapi.Address, error) {
	haddr := h.dispatchAddr(ctx, addr)
	return h.dialer.Dispatch(ctx, haddr)
}

func (h *Hosts) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	return h.dialer.Conn(ctx, h.dispatchAddr(ctx, addr))
}

func (h *Hosts) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	c, err := h.dialer.PacketConn(ctx, h.dispatchAddr(ctx, addr))
	if err != nil {
		return nil, err
	}
	return &dispatchPacketConn{c, h.dispatchAddr}, nil
}

type hostsKey struct{}

func (hostsKey) String() string { return "Hosts" }

func (h *Hosts) dispatchAddr(ctx context.Context, addr netapi.Address) netapi.Address {
	z, ok := h.hosts.Load(addr.Hostname())
	if ok {
		netapi.StoreFromContext(ctx).
			Add(hostsKey{}, addr.Hostname()).
			Add(netapi.CurrentKey{}, addr)
		return addr.OverrideHostname(z.Hostname())
	}

	z, ok = h.hosts.Load(addr.String())
	if ok {
		store := netapi.StoreFromContext(ctx)
		store.Add(hostsKey{}, addr.String())
		addr = addr.OverrideHostname(z.Hostname()).OverridePort(z.Port())
		store.Add(netapi.CurrentKey{}, addr)
	}

	return addr
}

func (h *Hosts) LookupIP(ctx context.Context, domain string) ([]net.IP, error) {
	addr := h.dispatchAddr(ctx, netapi.ParseAddressPort(0, domain, netapi.EmptyPort))
	if addr.Type() == netapi.IP {
		return []net.IP{yerror.Ignore(addr.IP(ctx))}, nil
	}

	return h.resolver.LookupIP(ctx, addr.Hostname())
}

func (h *Hosts) Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	addr := h.dispatchAddr(ctx, netapi.ParseAddressPort(0, strings.TrimSuffix(req.Name.String(), "."), netapi.EmptyPort))
	if req.Type != dnsmessage.TypeAAAA && req.Type != dnsmessage.TypeA {
		return h.resolver.Raw(ctx, req)
	}

	if addr.Type() != netapi.IP {
		name, err := dnsmessage.NewName(addr.Hostname() + ".")
		if err != nil {
			return dnsmessage.Message{}, err
		}
		req.Name = name
		return h.resolver.Raw(ctx, req)
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 0,
			Response:           true,
			Authoritative:      false,
			RecursionDesired:   false,
			RCode:              dnsmessage.RCodeSuccess,
			RecursionAvailable: false,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  req.Name,
				Type:  req.Type,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	if req.Type == dnsmessage.TypeAAAA {
		msg.Answers = []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  req.Name,
					Class: dnsmessage.ClassINET,
					TTL:   600,
					Type:  dnsmessage.TypeAAAA,
				},
				Body: &dnsmessage.AAAAResource{AAAA: [16]byte(yerror.Ignore(addr.IP(ctx)).To16())},
			},
		}
	}

	if req.Type == dnsmessage.TypeA {
		msg.Answers = []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  req.Name,
					Class: dnsmessage.ClassINET,
					TTL:   600,
					Type:  dnsmessage.TypeA,
				},
				Body: &dnsmessage.AResource{A: [4]byte(yerror.Ignore(addr.IP(ctx)).To4())},
			},
		}
	}

	return msg, nil
}

func (h *Hosts) Close() error { return nil }

package resolver

import (
	"context"
	"net"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
	"golang.org/x/net/dns/dnsmessage"
)

type Hosts struct {
	hosts    map[string]*hostsEntry
	dialer   netapi.Proxy
	resolver netapi.Resolver
}

type hostsEntry struct {
	V       netapi.Address
	portMap map[uint16]netapi.Address
}

func NewHosts(dialer netapi.Proxy, resolver netapi.Resolver) *Hosts {
	return &Hosts{dialer: dialer, resolver: resolver, hosts: map[string]*hostsEntry{}}
}

func (h *Hosts) Update(c *config.Setting) {
	store := map[string]*hostsEntry{}

	for k, v := range c.Dns.Hosts {
		_, _, e1 := net.SplitHostPort(k)
		_, _, e2 := net.SplitHostPort(v)

		if e1 == nil && e2 == nil {
			kaddr, err1 := netapi.ParseAddress(0, k)
			addr, err2 := netapi.ParseAddress(0, v)
			if err1 == nil && err2 == nil && kaddr.Port().Port() != 0 && addr.Port().Port() != 0 {
				v, ok := store[kaddr.Hostname()]
				if !ok {
					v = &hostsEntry{}
					store[kaddr.Hostname()] = v
				}

				if v.portMap == nil {
					v.portMap = map[uint16]netapi.Address{}
				}

				v.portMap[kaddr.Port().Port()] = addr
			}
		}

		if e1 != nil && e2 != nil {
			he, ok := store[k]
			if !ok {
				he = &hostsEntry{}
				store[k] = he
			}

			he.V = netapi.ParseAddressPort(0, v, netapi.EmptyPort)
		}
	}

	h.hosts = store
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

func (h *Hosts) dispatchAddr(ctx context.Context, addr netapi.Address) netapi.Address {
	v, ok := h.hosts[addr.Hostname()]
	if !ok {
		return addr
	}

	if v.portMap != nil {
		z, ok := v.portMap[addr.Port().Port()]
		if ok {
			store := netapi.StoreFromContext(ctx)
			store.Add("Hosts", addr.String())
			addr = addr.OverrideHostname(z.Hostname()).OverridePort(z.Port())
			store.Add(netapi.CurrentKey{}, addr)
			return addr
		}
	}

	if v.V == nil {
		return addr
	}

	netapi.StoreFromContext(ctx).
		Add("Hosts", addr.Hostname()).
		Add(netapi.CurrentKey{}, addr)
	return addr.OverrideHostname(v.V.Hostname())

}

func (h *Hosts) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) ([]net.IP, error) {
	addr := h.dispatchAddr(ctx, netapi.ParseAddressPort(0, domain, netapi.EmptyPort))
	if addr.Type() == netapi.IP {
		return []net.IP{yerror.Ignore(addr.IP(ctx))}, nil
	}

	return h.resolver.LookupIP(ctx, addr.Hostname(), opts...)
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

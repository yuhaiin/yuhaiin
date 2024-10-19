package resolver

import (
	"context"
	"net"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"golang.org/x/net/dns/dnsmessage"
)

type Hosts struct {
	hosts    map[string]*hostsEntry
	ptrMap   map[string][]string
	dialer   netapi.Proxy
	resolver netapi.Resolver
}

type hostsEntry struct {
	Address netapi.Address
	portMap map[uint16]netapi.Address
}

func NewHosts(dialer netapi.Proxy, resolver netapi.Resolver) *Hosts {
	return &Hosts{
		dialer:   dialer,
		resolver: resolver,
		hosts:    map[string]*hostsEntry{},
		ptrMap:   map[string][]string{},
	}
}

func (h *Hosts) Update(c *config.Setting) {
	store := map[string]*hostsEntry{}
	ptrStore := map[string][]string{}

	getEntry := func(k string, initMap bool) *hostsEntry {
		x, ok := store[k]
		if !ok {
			x = &hostsEntry{}
			store[k] = x
		}

		if initMap && x.portMap == nil {
			x.portMap = map[uint16]netapi.Address{}
		}

		return x
	}

	for k, v := range c.Dns.Hosts {
		if k == "" || v == "" {
			continue
		}

		_, _, e1 := net.SplitHostPort(k)
		_, _, e2 := net.SplitHostPort(v)

		if e1 == nil && e2 == nil {
			kaddr, err1 := netapi.ParseAddress("", k)
			addr, err2 := netapi.ParseAddress("", v)
			if err1 == nil && err2 == nil && kaddr.Port() != 0 && addr.Port() != 0 {
				getEntry(kaddr.Hostname(), true).portMap[uint16(kaddr.Port())] = addr
				continue
			}
		}

		if e1 != nil && e2 != nil {
			addr := netapi.ParseAddressPort("", v, 0)
			getEntry(k, false).Address = addr
			if !addr.IsFqdn() {
				ptrStore[v] = append(ptrStore[v], k)
			}
		}
	}

	h.hosts = store
	h.ptrMap = ptrStore
}

func (h *Hosts) Dispatch(ctx context.Context, addr netapi.Address) (netapi.Address, error) {
	haddr := h.dispatchAddr(ctx, addr)
	return h.dialer.Dispatch(ctx, haddr)
}

func (h *Hosts) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	return h.dialer.Conn(ctx, h.dispatchAddr(ctx, addr))
}

func (h *Hosts) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	return h.dialer.PacketConn(ctx, h.dispatchAddr(ctx, addr))
}

func (h *Hosts) setHosts(ctx context.Context, pre netapi.Address) {
	netapi.GetContext(ctx).Hosts = pre
}

func (h *Hosts) dispatchAddr(ctx context.Context, addr netapi.Address) netapi.Address {
	v, ok := h.hosts[addr.Hostname()]
	if ok {
		if v.portMap != nil {
			z, ok := v.portMap[uint16(addr.Port())]
			if ok {
				h.setHosts(ctx, addr)
				return netapi.ParseAddressPort(addr.Network(), z.Hostname(), z.Port())
			}
		}

		if v.Address != nil {
			h.setHosts(ctx, addr)
			return netapi.ParseAddressPort(addr.Network(), v.Address.Hostname(), addr.Port())
		}
	}

	if addr.IsFqdn() {
		// try system hosts
		ips, _ := system.LookupStaticHost(addr.Hostname())
		if len(ips) > 0 {
			h.setHosts(ctx, addr)
			return netapi.ParseNetipAddr(addr.Network(), ips[0], addr.Port())
		}
	}

	return addr
}

func (h *Hosts) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) ([]net.IP, error) {
	addr := h.dispatchAddr(ctx, netapi.ParseAddressPort("", domain, 0))
	if !addr.IsFqdn() {
		return []net.IP{addr.(netapi.IPAddress).IP()}, nil
	}

	return h.resolver.LookupIP(ctx, addr.Hostname(), opts...)
}

func (h *Hosts) newDnsMsg(req dnsmessage.Question) dnsmessage.Message {
	return dnsmessage.Message{
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
}

func (h *Hosts) Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	if req.Type == dnsmessage.TypePTR {
		ip, err := dns.RetrieveIPFromPtr(req.Name.String())
		if err != nil {
			return h.resolver.Raw(ctx, req)
		}

		ipstr := ip.String()

		domains := append(h.ptrMap[ipstr], system.LookupStaticAddr(ip)...)
		if len(domains) == 0 {
			return h.resolver.Raw(ctx, req)
		}

		msg := h.newDnsMsg(req)

		for _, v := range domains {
			if v == "" {
				continue
			}

			v = system.AbsDomain(v)

			name, err := dnsmessage.NewName(v)
			if err != nil {
				continue
			}

			msg.Answers = append(msg.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  req.Name,
					Class: dnsmessage.ClassINET,
					TTL:   600,
					Type:  req.Type,
				},
				Body: &dnsmessage.PTRResource{
					PTR: name,
				},
			})
		}

		return msg, nil
	}

	if req.Type != dnsmessage.TypeAAAA && req.Type != dnsmessage.TypeA {
		return h.resolver.Raw(ctx, req)
	}

	domain := unsafe.String(unsafe.SliceData(req.Name.Data[0:req.Name.Length-1]), req.Name.Length-1)

	addr := netapi.ParseAddressPort("", domain, 0)
	if !addr.IsFqdn() {
		return h.resolver.Raw(ctx, req)
	}

	addr = h.dispatchAddr(ctx, addr)

	if addr.IsFqdn() {
		name, err := dnsmessage.NewName(system.AbsDomain(addr.Hostname()))
		if err != nil {
			return dnsmessage.Message{}, err
		}
		req.Name = name
		return h.resolver.Raw(ctx, req)
	}

	ip := addr.(netapi.IPAddress).IP()

	if req.Type == dnsmessage.TypeAAAA {
		msg := h.newDnsMsg(req)
		msg.Answers = []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  req.Name,
					Class: dnsmessage.ClassINET,
					TTL:   600,
					Type:  dnsmessage.TypeAAAA,
				},
				Body: &dnsmessage.AAAAResource{AAAA: [16]byte(ip.To16())},
			},
		}
		return msg, nil
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return h.resolver.Raw(ctx, req)
	}

	msg := h.newDnsMsg(req)
	msg.Answers = []dnsmessage.Resource{
		{
			Header: dnsmessage.ResourceHeader{
				Name:  req.Name,
				Class: dnsmessage.ClassINET,
				TTL:   600,
				Type:  dnsmessage.TypeA,
			},
			Body: &dnsmessage.AResource{A: [4]byte(ip4)},
		},
	}

	return msg, nil
}

func (h *Hosts) Close() error { return nil }

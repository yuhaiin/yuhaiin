package resolver

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"golang.org/x/net/dns/dnsmessage"
)

type Hosts struct {
	mu       sync.RWMutex
	store    *hostsStore
	dialer   netapi.Proxy
	resolver netapi.Resolver
}

func NewHosts(dialer netapi.Proxy, resolver netapi.Resolver) *Hosts {
	return &Hosts{
		dialer:   dialer,
		resolver: resolver,
		store:    newHostsStore(),
	}
}

func (h *Hosts) Apply(hosts map[string]string) {
	store := newHostsStore()

	for k, v := range hosts {
		if k == "" || v == "" {
			continue
		}

		addr, err := netapi.ParseAddress("", k)
		if err != nil {
			continue
		}

		taddr, err := netapi.ParseAddress("", v)
		if err != nil {
			continue
		}

		store.add(addr, taddr)
	}

	h.mu.Lock()
	h.store = store
	h.mu.Unlock()
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
	netapi.GetContext(ctx).SetHosts(pre)
}

func (h *Hosts) dispatchAddr(ctx context.Context, addr netapi.Address) netapi.Address {
	h.mu.RLock()
	x, ok := h.store.lookup(addr)
	h.mu.RUnlock()
	if ok {
		h.setHosts(ctx, addr)
		return x
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
		return []net.IP{addr.(netapi.IPAddress).AddrPort().Addr().AsSlice()}, nil
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
		ip, err := resolver.RetrieveIPFromPtr(req.Name.String())
		if err != nil {
			return h.resolver.Raw(ctx, req)
		}

		ipaddr, _ := netip.AddrFromSlice(ip)

		h.mu.RLock()
		ptrs := h.store.lookupPtr(ipaddr)
		h.mu.RUnlock()
		domains := append(ptrs, system.LookupStaticAddr(ip)...)
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

	ip := addr.(netapi.IPAddress).AddrPort().Addr()

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
				Body: &dnsmessage.AAAAResource{AAAA: ip.As16()},
			},
		}
		return msg, nil
	}

	if !ip.Is4() {
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
			Body: &dnsmessage.AResource{A: ip.As4()},
		},
	}

	return msg, nil
}

func (h *Hosts) Close() error { return nil }

type hostsEntry struct {
	Address netapi.Address
	portMap map[uint16]netapi.Address
}

func (h *hostsEntry) Get(addr netapi.Address) (netapi.Address, bool) {
	if h.portMap != nil && addr.Port() != 0 {
		z, ok := h.portMap[uint16(addr.Port())]
		if ok {
			return z, true
		}
	}

	return h.Address, h.Address != nil
}

type hostsStore struct {
	Hosts   map[string]*hostsEntry
	IPHosts map[netip.Addr]*hostsEntry
	PtrMap  map[netip.Addr][]string
}

func newHostsStore() *hostsStore {
	return &hostsStore{
		Hosts:   make(map[string]*hostsEntry),
		IPHosts: make(map[netip.Addr]*hostsEntry),
		PtrMap:  make(map[netip.Addr][]string),
	}
}

func (h *hostsStore) getEntry(addr netapi.Address, create bool) (*hostsEntry, bool) {
	if addr.IsFqdn() {
		x, ok := h.Hosts[addr.Hostname()]
		if !ok && create {
			x = &hostsEntry{}
			ok = true
			h.Hosts[addr.Hostname()] = x
		}
		return x, ok
	}

	x, ok := h.IPHosts[addr.(netapi.IPAddress).AddrPort().Addr()]
	if !ok && create {
		x = &hostsEntry{}
		ok = true
		h.IPHosts[addr.(netapi.IPAddress).AddrPort().Addr()] = x
	}
	return x, ok
}

func (h *hostsStore) lookup(addr netapi.Address) (netapi.Address, bool) {
	v, ok := h.getEntry(addr, false)
	if !ok {
		return nil, false
	}
	t, ok := v.Get(addr)
	if !ok {
		return nil, false
	}

	if t.Port() != 0 {
		return netapi.ParseAddressPort(addr.Network(), t.Hostname(), t.Port()), true
	}

	return netapi.ParseAddressPort(addr.Network(), t.Hostname(), addr.Port()), true
}

func (h *hostsStore) add(addr, taddr netapi.Address) {
	entry, _ := h.getEntry(addr, true)

	if addr.Port() != 0 && taddr.Port() != 0 {
		if entry.portMap == nil {
			entry.portMap = map[uint16]netapi.Address{}
		}

		entry.portMap[uint16(addr.Port())] = taddr
		return
	}

	entry.Address = netapi.ParseAddressPort("", taddr.Hostname(), 0)
	if !taddr.IsFqdn() && addr.IsFqdn() {
		taddrtmp := taddr.(netapi.IPAddress).AddrPort().Addr()
		h.PtrMap[taddrtmp] = append(h.PtrMap[taddrtmp], addr.Hostname())
	}
}

func (h *hostsStore) lookupPtr(addr netip.Addr) []string {
	return h.PtrMap[addr]
}

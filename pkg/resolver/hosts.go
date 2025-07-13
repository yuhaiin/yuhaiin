package resolver

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	dnssystem "github.com/Asutorufa/yuhaiin/pkg/net/dns/system"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"github.com/miekg/dns"
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
	dnssystem.RefreshCache()
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

func (h *Hosts) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	return h.dialer.Ping(ctx, h.dispatchAddr(ctx, addr))
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

func (h *Hosts) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	addr, err := netapi.ParseAddressPort("", domain, 0)
	if err != nil {
		return nil, err
	}

	addr = h.dispatchAddr(ctx, addr)
	if !addr.IsFqdn() {
		ip := addr.(netapi.IPAddress).AddrPort().Addr()
		if ip.Is4() {
			return &netapi.IPs{A: []net.IP{ip.AsSlice()}}, nil
		}

		return &netapi.IPs{AAAA: []net.IP{ip.AsSlice()}}, nil
	}

	return h.resolver.LookupIP(ctx, addr.Hostname(), opts...)
}

func (h *Hosts) newDnsMsg(req dns.Question) dns.Msg {
	return dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 0,
			Response:           true,
			Authoritative:      false,
			RecursionDesired:   false,
			Rcode:              dns.RcodeSuccess,
			RecursionAvailable: false,
		},
		Question: []dns.Question{
			{
				Name:   req.Name,
				Qtype:  req.Qtype,
				Qclass: dns.ClassINET,
			},
		},
	}
}

func (h *Hosts) Raw(ctx context.Context, req dns.Question) (dns.Msg, error) {
	if req.Qtype == dns.TypePTR {
		ip, err := resolver.RetrieveIPFromPtr(req.Name)
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

			msg.Answer = append(msg.Answer, &dns.PTR{
				Ptr: v,
			})
		}

		return msg, nil
	}

	if req.Qtype != dns.TypeAAAA && req.Qtype != dns.TypeA {
		return h.resolver.Raw(ctx, req)
	}

	domain := req.Name[:len(req.Name)-1]

	addr, err := netapi.ParseAddressPort("", domain, 0)
	if err != nil {
		return dns.Msg{}, err
	}

	if !addr.IsFqdn() {
		return h.resolver.Raw(ctx, req)
	}

	addr = h.dispatchAddr(ctx, addr)

	if addr.IsFqdn() {
		req.Name = system.AbsDomain(addr.Hostname())
		return h.resolver.Raw(ctx, req)
	}

	ip := addr.(netapi.IPAddress).AddrPort().Addr()

	if req.Qtype == dns.TypeAAAA {
		msg := h.newDnsMsg(req)
		msg.Answer = []dns.RR{
			&dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   req.Name,
					Rrtype: dns.TypeA,
					Ttl:    600,
					Class:  dns.ClassINET,
				},
				AAAA: ip.AsSlice(),
			},
		}
		return msg, nil
	}

	if !ip.Is4() {
		return h.resolver.Raw(ctx, req)
	}

	msg := h.newDnsMsg(req)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   req.Name,
				Rrtype: dns.TypeA,
				Ttl:    600,
				Class:  dns.ClassINET,
			},
			A: ip.AsSlice(),
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

	port := addr.Port()
	if t.Port() != 0 {
		port = t.Port()
	}

	addr, err := netapi.ParseAddressPort(addr.Network(), t.Hostname(), port)
	if err != nil {
		return nil, false
	}

	return addr, true
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

	var err error
	entry.Address, err = netapi.ParseAddressPort("", taddr.Hostname(), 0)
	if err != nil {
		log.Warn("parse host target failed", "err", err, "hostname", taddr.Hostname())
		return
	}

	if !taddr.IsFqdn() && addr.IsFqdn() {
		taddrtmp := taddr.(netapi.IPAddress).AddrPort().Addr()
		h.PtrMap[taddrtmp] = append(h.PtrMap[taddrtmp], addr.Hostname())
	}
}

func (h *hostsStore) lookupPtr(addr netip.Addr) []string {
	return h.PtrMap[addr]
}

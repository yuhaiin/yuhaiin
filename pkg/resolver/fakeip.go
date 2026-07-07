package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/cache"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/fakeip"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/server"
	dnssystem "github.com/Asutorufa/yuhaiin/pkg/net/dns/system"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/domain"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"github.com/miekg/dns"
)

type Fakedns struct {
	dialer   netapi.Proxy
	upstream netapi.Resolver
	dbPath   string
	legacy   cache.Cache

	dnsServer netapi.DNSAgent
	fake      *fakeip.FakeDNS

	whitelist *domain.Fqdn[struct{}]
	skipCheck *domain.Fqdn[struct{}]

	serverHost string

	whitelistSlice []string
	skipCheckSlice []string

	smu     sync.RWMutex
	enabled atomic.Bool
}

func NewFakeDNS(dialer netapi.Proxy, upstream netapi.Resolver, dbPath string, legacy cache.Cache, initial ...*config.FakednsConfig) (*Fakedns, error) {
	ipv4Range, _ := netip.ParsePrefix("10.2.0.1/24")
	ipv6Range, _ := netip.ParsePrefix("fc00::/64")
	if len(initial) > 0 && initial[0] != nil {
		ipv4Range = configuration.GetFakeIPRange(initial[0].GetIpv4Range(), false)
		ipv6Range = configuration.GetFakeIPRange(initial[0].GetIpv6Range(), true)
	}

	fake, err := fakeip.NewFakeDNS(upstream, ipv4Range, ipv6Range, dbPath, legacy)
	if err != nil {
		return nil, err
	}

	f := &Fakedns{
		fake:      fake,
		dialer:    dialer,
		upstream:  upstream,
		dbPath:    dbPath,
		legacy:    legacy,
		whitelist: domain.NewTrie[struct{}](),
		skipCheck: domain.NewTrie[struct{}](),
	}
	f.dnsServer = server.NewServer("", f)

	return f, nil
}

func (f *Fakedns) Apply(c *config.FakednsConfig) {
	defer dnssystem.RefreshCache()

	f.enabled.Store(c.GetEnabled())

	if !slices.Equal(c.GetSkipCheckList(), f.skipCheckSlice) {
		d := domain.NewTrie[struct{}]()

		for _, v := range c.GetSkipCheckList() {
			d.Insert(v, struct{}{})
		}
		f.skipCheck = d
		f.skipCheckSlice = c.GetSkipCheckList()
	}

	if !slices.Equal(c.GetWhitelist(), f.whitelistSlice) {
		d := domain.NewTrie[struct{}]()

		for _, v := range c.GetWhitelist() {
			d.Insert(v, struct{}{})
		}

		// skip tailscale login url, because tailscale client will use default
		// interface to connect controlplane, so we can't use fake ip for it
		// d.Insert(strings.TrimPrefix(ipn.DefaultControlURL, "https://"), struct{}{})
		// d.Insert(logtail.DefaultHost, struct{}{})
		// d.Insert("login.tailscale.com", struct{}{})

		f.whitelist = d
		f.whitelistSlice = c.GetWhitelist()
	}

	ipRange := configuration.GetFakeIPRange(c.GetIpv4Range(), false)
	ipv6Range := configuration.GetFakeIPRange(c.GetIpv6Range(), true)

	if f.fake.Equal(ipRange, ipv6Range) {
		return
	}

	next, err := fakeip.NewFakeDNS(f.upstream, ipRange, ipv6Range, f.dbPath, f.legacy)
	if err != nil {
		log.Error("reload sqlite fakeip pool failed", "err", err)
		return
	}

	old := f.fake
	f.fake = next
	if old != nil {
		_ = old.Close()
	}
}

func (f *Fakedns) resolver(ctx context.Context, domain string) netapi.Resolver {
	metrics.Counter.AddDNSProcess(domain)

	if f.enabled.Load() || netapi.GetContext(ctx).ConnOptions().Resolver().UseFakeIP() {
		if _, ok := f.whitelist.SearchString(system.RelDomain(domain)); ok {
			return f.upstream
		}

		return f.fake
	}

	return f.upstream
}

func (f *Fakedns) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	if _, ok := f.skipCheck.SearchString(system.RelDomain(domain)); ok {
		netapi.GetContext(ctx).ConnOptions().Resolver().SetFakeIPSkipCheckUpstream(ok)
	}
	return f.resolver(ctx, domain).LookupIP(ctx, domain, opts...)
}

func (f *Fakedns) Raw(ctx context.Context, req dns.Question) (dns.Msg, error) {
	if req.Qtype == dns.TypeAAAA || req.Qtype == dns.TypeA {
		if _, ok := f.skipCheck.SearchString(system.RelDomain(req.Name)); ok {
			netapi.GetContext(ctx).ConnOptions().Resolver().SetFakeIPSkipCheckUpstream(ok)
		}
	}
	return f.resolver(ctx, req.Name).Raw(ctx, req)
}

func (f *Fakedns) Close() error {
	var err error
	if er := f.upstream.Close(); er != nil {
		err = errors.Join(err, er)
	}

	f.smu.Lock()
	defer f.smu.Unlock()

	if f.dnsServer != nil {
		if er := f.dnsServer.Close(); er != nil {
			err = errors.Join(err, er)
		}
		f.dnsServer = nil
	}
	if f.fake != nil {
		if er := f.fake.Close(); er != nil {
			err = errors.Join(err, er)
		}
		f.fake = nil
	}

	return err
}

func (f *Fakedns) Name() string { return "fakedns" }

func (f *Fakedns) Dispatch(ctx context.Context, addr netapi.Address) (netapi.Address, error) {
	return f.dialer.Dispatch(ctx, f.dispatchAddr(ctx, addr))
}

func (f *Fakedns) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	return f.dialer.Conn(ctx, f.dispatchAddr(ctx, addr))
}

func (f *Fakedns) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	return f.dialer.PacketConn(ctx, f.dispatchAddr(ctx, addr))
}

func (f *Fakedns) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	return f.dialer.Ping(ctx, f.dispatchAddr(ctx, addr))
}

func (f *Fakedns) dispatchAddr(ctx context.Context, addr netapi.Address) netapi.Address {
	if addr.IsFqdn() {
		return addr
	}

	addrPort := addr.(netapi.IPAddress).AddrPort()

	if !f.fake.Contains(addrPort.Addr()) {
		return addr
	}

	store := netapi.GetContext(ctx)

	t, ok := f.fake.GetDomainFromIP(addrPort.Addr())
	if ok {
		store.SetFakeIP(addr)
		z, err := netapi.ParseAddressPort(addr.Network(), t, addr.Port())
		if err == nil {
			return z
		} else {
			log.Warn("parse fakeip reverse domain failed", "addr", t, "err", err)
		}
	}

	if configuration.FakeIPEnabled.Load() {
		// block fakeip range to prevent infinite loop which taget ip is not found in fakeip cache
		store.ConnOptions().SetRouteMode(config.Mode_block)
	}

	return addr
}

func (a *Fakedns) SetServer(s string) {
	var old netapi.DNSAgent

	a.smu.Lock()
	if a.serverHost == s {
		a.smu.Unlock()
		return
	}
	if a.dnsServer != nil {
		old = a.dnsServer
	}
	a.dnsServer = nil
	a.serverHost = s
	a.smu.Unlock()

	if old != nil {
		if err := old.Close(); err != nil {
			log.Error("close dns server failed", "err", err)
		}
	}

	next := server.NewServer(s, a)

	a.smu.Lock()
	a.dnsServer = next
	a.smu.Unlock()
}

func (a *Fakedns) server() netapi.DNSAgent {
	a.smu.RLock()
	defer a.smu.RUnlock()
	return a.dnsServer
}

func (a *Fakedns) DoStream(ctx context.Context, req *netapi.DNSStreamRequest) error {
	s := a.server()
	if s == nil {
		return fmt.Errorf("dns server is not initialized")
	}
	return s.DoStream(ctx, req)
}

func (a *Fakedns) DoDatagram(ctx context.Context, req *netapi.DNSRawRequest) error {
	s := a.server()
	if s == nil {
		return fmt.Errorf("dns server is not initialized")
	}
	return s.DoDatagram(ctx, req)
}

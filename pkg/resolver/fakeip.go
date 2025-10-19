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

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/server"
	dnssystem "github.com/Asutorufa/yuhaiin/pkg/net/dns/system"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/domain"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"github.com/miekg/dns"
)

type Fakedns struct {
	dialer   netapi.Proxy
	upstream netapi.Resolver
	db       cache.RecursionCache
	fake     *resolver.FakeDNS

	whitelist *domain.Fqdn[struct{}]
	skipCheck *domain.Fqdn[struct{}]

	whitelistSlice []string
	skipCheckSlice []string
	enabled        atomic.Bool

	smu        sync.RWMutex
	dnsServer  netapi.DNSServer
	serverHost string
}

func NewFakeDNS(dialer netapi.Proxy, upstream netapi.Resolver, db cache.RecursionCache) *Fakedns {
	ipv4Range, _ := netip.ParsePrefix("10.2.0.1/24")
	ipv6Range, _ := netip.ParsePrefix("fc00::/64")

	f := &Fakedns{
		fake:      resolver.NewFakeDNS(upstream, ipv4Range, ipv6Range, db),
		dialer:    dialer,
		upstream:  upstream,
		db:        db,
		whitelist: domain.NewDomainMapper[struct{}](),
		skipCheck: domain.NewDomainMapper[struct{}](),
	}
	f.dnsServer = server.NewServer("", f)

	return f
}

func (f *Fakedns) Apply(c *config.FakednsConfig) {
	defer dnssystem.RefreshCache()

	f.enabled.Store(c.GetEnabled())

	if !slices.Equal(c.GetSkipCheckList(), f.skipCheckSlice) {
		d := domain.NewDomainMapper[struct{}]()

		for _, v := range c.GetSkipCheckList() {
			d.Insert(v, struct{}{})
		}
		f.skipCheck = d
		f.skipCheckSlice = c.GetSkipCheckList()
	}

	if !slices.Equal(c.GetWhitelist(), f.whitelistSlice) {
		d := domain.NewDomainMapper[struct{}]()

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

	if f.fake != nil {
		f.fake.Flush()
	}

	f.fake = resolver.NewFakeDNS(f.upstream, ipRange, ipv6Range, f.db)
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
	if f.fake != nil {
		f.fake.Flush()
	}

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
	a.smu.Lock()
	defer a.smu.Unlock()

	if a.serverHost == s {
		return
	}

	if a.dnsServer != nil {
		if err := a.dnsServer.Close(); err != nil {
			log.Error("close dns server failed", "err", err)
		}
		a.dnsServer = nil
	}

	a.dnsServer = server.NewServer(s, a)
	a.serverHost = s
}

func (a *Fakedns) server() netapi.DNSServer {
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

func (a *Fakedns) Do(ctx context.Context, req *netapi.DNSRawRequest) error {
	s := a.server()
	if s == nil {
		return fmt.Errorf("dns server is not initialized")
	}
	return s.Do(ctx, req)
}

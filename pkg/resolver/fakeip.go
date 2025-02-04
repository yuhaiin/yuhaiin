package resolver

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/domain"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	cd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"go.etcd.io/bbolt"
	"golang.org/x/net/dns/dnsmessage"
)

type Fakedns struct {
	dialer   netapi.Proxy
	upstream netapi.Resolver
	db       *bbolt.DB
	fake     *resolver.FakeDNS

	whitelist *domain.Fqdn[struct{}]

	whitelistSlice []string
	enabled        atomic.Bool
}

func NewFakeDNS(dialer netapi.Proxy, upstream netapi.Resolver, db *bbolt.DB) *Fakedns {
	ipv4Range, _ := netip.ParsePrefix("10.2.0.1/24")
	ipv6Range, _ := netip.ParsePrefix("fc00::/64")

	return &Fakedns{
		fake:      resolver.NewFakeDNS(upstream, ipv4Range, ipv6Range, db),
		dialer:    dialer,
		upstream:  upstream,
		db:        db,
		whitelist: domain.NewDomainMapper[struct{}](),
	}
}

func (f *Fakedns) Apply(c *cd.FakednsConfig) {
	f.enabled.Store(c.GetEnabled())

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

	if f.enabled.Load() || ctx.Value(netapi.ForceFakeIPKey{}) == true {
		if _, ok := f.whitelist.SearchString(system.RelDomain(domain)); ok {
			return f.upstream
		}

		return f.fake
	}

	return f.upstream
}

func (f *Fakedns) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) ([]net.IP, error) {
	return f.resolver(ctx, domain).LookupIP(ctx, domain, opts...)
}

func (f *Fakedns) Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	return f.resolver(ctx, req.Name.String()).Raw(ctx, req)
}

func (f *Fakedns) Close() error {
	if f.fake != nil {
		f.fake.Flush()
	}
	return f.upstream.Close()
}

func (f *Fakedns) Dispatch(ctx context.Context, addr netapi.Address) (netapi.Address, error) {
	return f.dialer.Dispatch(ctx, f.dispatchAddr(ctx, addr))
}

func (f *Fakedns) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	return f.dialer.Conn(ctx, f.dispatchAddr(ctx, addr))
}

func (f *Fakedns) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	return f.dialer.PacketConn(ctx, f.dispatchAddr(ctx, addr))
}

func (f *Fakedns) dispatchAddr(ctx context.Context, addr netapi.Address) netapi.Address {
	if addr.IsFqdn() {
		return addr
	}

	addrPort, _ := dialer.ResolverAddrPort(ctx, addr)

	if !f.fake.Contains(addrPort.Addr()) {
		return addr
	}

	store := netapi.GetContext(ctx)

	t, ok := f.fake.GetDomainFromIP(addrPort.Addr())
	if ok {
		store.FakeIP = addr
		return netapi.ParseAddressPort(addr.Network(), t, addr.Port())
	}

	if configuration.FakeIPEnabled.Load() {
		// block fakeip range to prevent infinite loop which taget ip is not found in fakeip cache
		store.ForceMode = bypass.Mode_block
	}

	return addr
}

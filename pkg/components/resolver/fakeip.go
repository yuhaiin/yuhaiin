package resolver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/domain"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
	"golang.org/x/net/dns/dnsmessage"
)

type Fakedns struct {
	enabled        bool
	inboundEnabled bool

	fake *dns.FakeDNS

	dialer   netapi.Proxy
	upstream netapi.Resolver
	cache    *cache.Cache
	cachev6  *cache.Cache

	whitelistSlice []string
	whitelist      *domain.Fqdn[struct{}]
}

func NewFakeDNS(dialer netapi.Proxy, upstream netapi.Resolver, bbolt, bboltv6 *cache.Cache) *Fakedns {
	ipv4Range := yerror.Ignore(netip.ParsePrefix("10.2.0.1/24"))
	ipv6Range := yerror.Ignore(netip.ParsePrefix("fc00::/64"))

	return &Fakedns{
		fake:      dns.NewFakeDNS(upstream, ipv4Range, ipv6Range, bbolt, bboltv6),
		dialer:    dialer,
		upstream:  upstream,
		cache:     bbolt,
		cachev6:   bboltv6,
		whitelist: domain.NewDomainMapper[struct{}](),
	}
}

func (f *Fakedns) Update(c *pc.Setting) {
	f.enabled = c.Dns.Fakedns
	f.inboundEnabled = c.Server.HijackDnsFakeip

	if !slices.Equal(c.Dns.FakednsWhitelist, f.whitelistSlice) {
		d := domain.NewDomainMapper[struct{}]()

		for _, v := range c.Dns.FakednsWhitelist {
			d.Insert(v, struct{}{})
		}

		f.whitelist = d
		f.whitelistSlice = c.Dns.FakednsWhitelist
	}

	ipRange := configuration.GetFakeIPRange(c.Dns.FakednsIpRange, false)
	ipv6Range := configuration.GetFakeIPRange(c.Dns.FakednsIpv6Range, true)

	if f.fake.Equal(ipRange, ipv6Range) {
		return
	}

	f.fake = dns.NewFakeDNS(f.upstream, ipRange, ipv6Range, f.cache, f.cachev6)
}

func (f *Fakedns) resolver(ctx context.Context, domain string) netapi.Resolver {
	if f.enabled || ctx.Value(netapi.ForceFakeIP{}) == true {
		if _, ok := f.whitelist.SearchString(strings.TrimSuffix(domain, ".")); ok {
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

func (f *Fakedns) Close() error { return f.upstream.Close() }

func (f *Fakedns) Dispatch(ctx context.Context, addr netapi.Address) (netapi.Address, error) {
	return f.dialer.Dispatch(ctx, f.dispatchAddr(ctx, addr))
}

func (f *Fakedns) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	c, err := f.dialer.Conn(ctx, f.dispatchAddr(ctx, addr))
	if err != nil {
		return nil, fmt.Errorf("connect tcp to %s failed: %w", addr, err)
	}

	return c, nil
}

func (f *Fakedns) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	c, err := f.dialer.PacketConn(ctx, f.dispatchAddr(ctx, addr))
	if err != nil {
		return nil, fmt.Errorf("connect udp to %s failed: %w", addr, err)
	}

	c = &dispatchPacketConn{c, f.dispatchAddr}

	return c, nil
}

func (f *Fakedns) dispatchAddr(ctx context.Context, addr netapi.Address) netapi.Address {
	if addr.Type() != netapi.IP {
		return addr
	}
	addrPort := addr.AddrPort(ctx).V.Addr()

	if !f.fake.Contains(addrPort) {
		return addr
	}

	store := netapi.GetContext(ctx)

	t, ok := f.fake.GetDomainFromIP(addrPort)
	if ok {
		r := addr.OverrideHostname(t)
		store.FakeIP = addr
		store.Current = r
		return r
	}

	if f.enabled || f.inboundEnabled {
		// block fakeip range to prevent infinite loop which taget ip is not found in fakeip cache
		store.ForceMode = bypass.Mode_block
	}

	return addr
}

type dispatchPacketConn struct {
	net.PacketConn
	dispatch func(context.Context, netapi.Address) netapi.Address
}

func (f *dispatchPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	z, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("parse addr failed: %w", err)
	}

	return f.PacketConn.WriteTo(b, f.dispatch(context.TODO(), z))
}

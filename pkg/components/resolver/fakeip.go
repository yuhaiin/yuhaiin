package resolver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/domain"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
	"golang.org/x/net/dns/dnsmessage"
)

type Fakedns struct {
	enabled  bool
	fake     *dns.FakeDNS
	dialer   netapi.Proxy
	upstream netapi.Resolver
	cache    *cache.Cache
	cachev6  *cache.Cache

	whitelistSlice []string
	whitelist      *domain.Fqdn[struct{}]
}

func NewFakeDNS(dialer netapi.Proxy, upstream netapi.Resolver, bbolt, bboltv6 *cache.Cache) *Fakedns {
	return &Fakedns{
		fake: dns.NewFakeDNS(upstream,
			yerror.Ignore(netip.ParsePrefix("10.2.0.1/24")),
			yerror.Ignore(netip.ParsePrefix("fc00::/64")),
			bbolt, bboltv6),
		dialer:    dialer,
		upstream:  upstream,
		cache:     bbolt,
		cachev6:   bboltv6,
		whitelist: domain.NewDomainMapper[struct{}](),
	}
}

func (f *Fakedns) Update(c *pc.Setting) {
	f.enabled = c.Dns.Fakedns

	if !slices.Equal(c.Dns.FakednsWhitelist, f.whitelistSlice) {
		log.Info("update fakedns whitelist", "old", f.whitelistSlice, "new", c.Dns.FakednsWhitelist)

		d := domain.NewDomainMapper[struct{}]()

		for _, v := range c.Dns.FakednsWhitelist {
			d.Insert(v, struct{}{})
		}

		f.whitelist = d
		f.whitelistSlice = c.Dns.FakednsWhitelist
	}

	ipRange, er4 := netip.ParsePrefix(c.Dns.FakednsIpRange)
	if er4 != nil {
		log.Error("parse fakedns ip range failed", "err", er4)
		ipRange, _ = netip.ParsePrefix("10.2.0.1/24")
	}

	ipv6Range, er6 := netip.ParsePrefix(c.Dns.FakednsIpv6Range)
	if er6 != nil {
		log.Error("parse fakedns PreferIPv6 range failed", "err", er6)
		ipv6Range, _ = netip.ParsePrefix("fc00::/64")
	}

	if er4 != nil && er6 != nil {
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
	if addr.Type() == netapi.IP {
		t, ok := f.fake.GetDomainFromIP(addr.AddrPort(ctx).V.Addr())
		if ok {
			r := addr.OverrideHostname(t)
			netapi.StoreFromContext(ctx).
				Add(netapi.FakeIPKey{}, addr).
				Add(netapi.CurrentKey{}, r)
			return r
		}
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

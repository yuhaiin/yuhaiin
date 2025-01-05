package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	dr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/protobuf/proto"
)

type Entry struct {
	Resolver netapi.Resolver
	Config   *pd.Dns
}

type Resolver struct {
	dialer          netapi.Proxy
	bootstrapConfig *pd.Dns
	store           syncmap.SyncMap[string, *Entry]
	resolvers       *atomicx.Value[map[string]*pd.Dns]
	ipv6            atomic.Bool
	direct          *atomicx.Value[string]
	proxy           *atomicx.Value[string]
}

func NewResolver(dd netapi.Proxy) *Resolver {
	dialer.InternetResolver, _ = dns.New(dns.Config{
		Type:   pd.Type_udp,
		Host:   "8.8.8.8:53",
		Name:   "internet",
		Dialer: dr.Default,
	})
	return &Resolver{
		dialer:    dd,
		resolvers: atomicx.NewValue(make(map[string]*pd.Dns)),
		direct:    atomicx.NewValue(""),
		proxy:     atomicx.NewValue(""),
	}
}

var errorResolver = &Entry{
	Resolver: netapi.ErrorResolver(func(domain string) error {
		return &net.OpError{
			Op:   "block",
			Addr: netapi.ParseDomainPort("", domain, 0),
			Err:  errors.New("blocked"),
		}
	}),
}

var block = bypass.Mode_block.String()
var proxy = bypass.Mode_proxy.String()
var direct = bypass.Mode_direct.String()

func (r *Resolver) getFallbackResolver(str, fallback string) *Entry {
	if fallback == block {
		return errorResolver
	}

	if str != "" {
		z, ok := r.getResolver(str)
		if ok {
			return z
		}
	}

	if fallback == "" {
		return nil
	}

	var network string
	if fallback == proxy {
		network = r.proxy.Load()
	}

	if fallback == direct {
		network = r.direct.Load()
	}

	if network != "" {
		z, ok := r.getResolver(network)
		if ok {
			return z
		}
	}

	z, ok := r.getResolver(fallback)
	if ok {
		return z
	}

	return nil
}

func (r *Resolver) Get(str, fallback string) netapi.Resolver {
	z := r.getFallbackResolver(str, fallback)
	if z != nil {
		return z.Resolver
	}

	z, ok := r.getResolver(proxy)
	if ok {
		return z.Resolver
	}

	return dialer.Bootstrap
}

func (r *Resolver) Close() error {
	for _, v := range r.store.Range {
		v.Resolver.Close()
	}

	r.store = syncmap.SyncMap[string, *Entry]{}

	return nil
}

func (r *Resolver) getResolver(str string) (*Entry, bool) {
	e, ok := r.store.Load(str)
	if ok {
		return e, true
	}

	e, _, err := r.store.LoadOrCreate(str, func() (*Entry, error) {
		config, ok := r.resolvers.Load()[str]
		if !ok {
			return nil, fmt.Errorf("resolver %s not found", str)
		}

		dialer := &dnsDialer{
			Proxy: r.dialer,
			addr: func(ctx context.Context, addr netapi.Address) {
				store := netapi.GetContext(ctx)
				store.Component = "Resolver " + str
				// force to use bootstrap dns, otherwise will dns query cycle
				store.Resolver.ResolverSelf = dialer.Bootstrap
			},
		}

		z, err := newDNS(str, config, dialer, r)
		if err != nil {
			return nil, err
		}

		return &Entry{
			Resolver: z,
			Config:   config,
		}, nil
	})

	return e, err == nil
}

func (r *Resolver) GetIPv6() bool { return r.ipv6.Load() }

func (r *Resolver) Update(c *pc.Setting) {
	if c.Dns.Resolver == nil {
		c.Dns.Resolver = make(map[string]*pd.Dns)
	}

	c.Dns.Resolver["bootstrap"] = c.Dns.Bootstrap
	c.Dns.Resolver[direct] = c.Dns.Local
	c.Dns.Resolver[proxy] = c.Dns.Remote

	r.direct.Store(c.Bypass.DirectResolver)
	r.proxy.Store(c.Bypass.ProxyResolver)
	r.ipv6.Store(c.GetIpv6())
	r.resolvers.Store(c.Dns.Resolver)

	if !proto.Equal(r.bootstrapConfig, c.Dns.Bootstrap) {
		dd := &dnsDialer{
			Proxy: r.dialer,
			addr: func(ctx context.Context, addr netapi.Address) {
				store := netapi.GetContext(ctx)
				store.ForceMode = bypass.Mode_direct
				store.Component = "Resolver BOOTSTRAP"
				store.Resolver.ResolverSelf = dialer.InternetResolver
			},
		}
		z, err := newDNS("BOOTSTRAP", c.Dns.Bootstrap, dd, r)
		if err != nil {
			log.Error("get bootstrap dns failed", "err", err)
		} else {
			old := dialer.Bootstrap
			dialer.Bootstrap = z
			old.Close()
		}
	}

	for key, value := range r.store.Range {
		ndns, ok := c.Dns.Resolver[key]
		if !ok || !proto.Equal(value.Config, ndns) {
			r.store.Delete(key)
			if err := value.Resolver.Close(); err != nil {
				log.Error("close dns resolver failed", "key", key, "err", err)
			}
		}
	}
}

type dnsWrap struct {
	dns      netapi.Resolver
	resolver *Resolver
	name     string
}

func wrap(name string, dns netapi.Resolver, v6 *Resolver) *dnsWrap {
	return &dnsWrap{name: name, dns: dns, resolver: v6}
}

func (d *dnsWrap) LookupIP(ctx context.Context, host string, opts ...func(*netapi.LookupIPOption)) ([]net.IP, error) {
	opt := func(opt *netapi.LookupIPOption) {
		if d.resolver.GetIPv6() {
			opt.Mode = netapi.ResolverModeNoSpecified
		} else {
			opt.Mode = netapi.ResolverModePreferIPv4
		}

		for _, o := range opts {
			o(opt)
		}
	}

	ips, err := d.dns.LookupIP(ctx, host, opt)
	if err != nil {
		return nil, fmt.Errorf("%s lookup failed: %w", d.name, err)
	}

	return ips, nil
}

func (d *dnsWrap) Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	msg, err := d.dns.Raw(ctx, req)
	if err != nil {
		return dnsmessage.Message{}, fmt.Errorf("%s do raw dns request failed: %w", d.name, err)
	}

	return msg, nil
}

func (d *dnsWrap) Close() error {
	if d.dns != nil {
		return d.dns.Close()
	}

	return nil
}

func newDNS(name string, dc *pd.Dns, dialer netapi.Proxy, resovler *Resolver) (netapi.Resolver, error) {
	subnet, err := netip.ParsePrefix(dc.Subnet)
	if err != nil {
		p, err := netip.ParseAddr(dc.Subnet)
		if err == nil {
			subnet = netip.PrefixFrom(p, p.BitLen())
		}
	}
	r, err := dns.New(
		dns.Config{
			Type:       dc.Type,
			Name:       name,
			Host:       dc.Host,
			Servername: dc.TlsServername,
			Subnet:     subnet,
			Dialer:     dialer,
		})
	if err != nil {
		return nil, err
	}

	return wrap(name, r, resovler), nil
}

type dnsDialer struct {
	netapi.Proxy
	addr func(ctx context.Context, addr netapi.Address)
}

func (d *dnsDialer) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	ctx = netapi.WithContext(ctx)
	d.addr(ctx, addr)
	return d.Proxy.Conn(ctx, addr)
}

func (d *dnsDialer) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	ctx = netapi.WithContext(ctx)
	d.addr(ctx, addr)
	return d.Proxy.PacketConn(ctx, addr)
}

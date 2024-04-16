package resolver

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/components/shunt"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/protobuf/proto"
)

type Entry struct {
	Resolver netapi.Resolver
	Config   *pd.Dns
}

type Resolver struct {
	ipv6            bool
	dialer          netapi.Proxy
	bootstrapConfig *pd.Dns
	store           syncmap.SyncMap[string, *Entry]
}

func NewResolver(dialer netapi.Proxy) *Resolver {
	return &Resolver{dialer: dialer}
}

var errorResolver = netapi.ErrorResolver(func(domain string) error {
	return fmt.Errorf("%w: %s", netapi.ErrBlocked, domain)
})
var blockStr = bypass.Mode_block.String()

func (r *Resolver) Get(str string) netapi.Resolver {
	if str != "" {
		if str == blockStr {
			return errorResolver
		}
		z, ok := r.store.Load(str)
		if ok {
			return z.Resolver
		}
	}

	z, ok := r.store.Load(bypass.Mode_proxy.String())
	if ok {
		return z.Resolver
	}

	return netapi.Bootstrap
}

func (r *Resolver) Close() error {
	r.store.Range(func(k string, v *Entry) bool {
		v.Resolver.Close()
		return true
	})

	r.store = syncmap.SyncMap[string, *Entry]{}

	return nil
}

func (r *Resolver) GetIPv6() bool {
	return r.ipv6
}

func (r *Resolver) Update(c *pc.Setting) {
	c.Dns.Resolver = map[string]*pd.Dns{
		bypass.Mode_direct.String(): c.Dns.Local,
		bypass.Mode_proxy.String():  c.Dns.Remote,
	}

	r.ipv6 = c.GetIpv6()

	if !proto.Equal(r.bootstrapConfig, c.Dns.Bootstrap) {
		dialer := &dialer{
			Proxy: r.dialer,
			addr: func(ctx context.Context, addr netapi.Address) {
				netapi.StoreFromContext(ctx).Add("Component", "Resolver BOOTSTRAP")
				netapi.StoreFromContext(ctx).Add(shunt.ForceModeKey{}, bypass.Mode_direct)
				addr.SetResolver(netapi.InternetResolver)
				addr.SetSrc(netapi.AddressSrcDNS)
			},
		}
		z, err := newDNS("BOOTSTRAP", c.Dns.Bootstrap, dialer, r)
		if err != nil {
			log.Error("get bootstrap dns failed", "err", err)
		} else {
			old := netapi.Bootstrap
			netapi.Bootstrap = z
			old.Close()
		}
	}

	for k, v := range c.Dns.Resolver {
		entry, ok := r.store.Load(k)
		if ok && proto.Equal(entry.Config, v) {
			continue
		}

		if entry != nil {
			if err := entry.Resolver.Close(); err != nil {
				log.Error("close dns resolver failed", "key", k, "err", err)
			}
		}

		r.store.Delete(k)

		dialer := &dialer{
			Proxy: r.dialer,
			addr: func(ctx context.Context, addr netapi.Address) {
				netapi.StoreFromContext(ctx).Add("Component", "Resolver "+k)
				// force to use bootstrap dns, otherwise will dns query cycle
				addr.SetResolver(netapi.Bootstrap)
				addr.SetSrc(netapi.AddressSrcDNS)
			},
		}

		z, err := newDNS(k, v, dialer, r)
		if err != nil {
			log.Error("get local dns failed", "err", err)
		} else {
			r.store.Store(k, &Entry{
				Resolver: z,
				Config:   v,
			})
		}
	}

	r.store.Range(func(key string, value *Entry) bool {
		_, ok := c.Dns.Resolver[key]
		if !ok {
			if err := value.Resolver.Close(); err != nil {
				log.Error("close dns resolver failed", "key", key, "err", err)
			}
			r.store.Delete(key)
		}
		return true
	})
}

type dnsWrap struct {
	name     string
	dns      netapi.Resolver
	resolver *Resolver
}

func wrap(name string, dns netapi.Resolver, v6 *Resolver) *dnsWrap {
	return &dnsWrap{name: name, dns: dns, resolver: v6}
}

func (d *dnsWrap) LookupIP(ctx context.Context, host string, opts ...func(*netapi.LookupIPOption)) ([]net.IP, error) {
	opt := func(opt *netapi.LookupIPOption) {
		if d.resolver.GetIPv6() {
			opt.AAAA = true
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

type dialer struct {
	netapi.Proxy
	addr func(ctx context.Context, addr netapi.Address)
}

func (d *dialer) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	ctx = netapi.NewStore(ctx)
	d.addr(ctx, addr)
	return d.Proxy.Conn(ctx, addr)
}

func (d *dialer) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	ctx = netapi.NewStore(ctx)
	d.addr(ctx, addr)
	return d.Proxy.PacketConn(ctx, addr)
}

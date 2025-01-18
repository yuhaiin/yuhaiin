package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	dr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	cd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Entry struct {
	Resolver netapi.Resolver
	Config   *pd.Dns
}

type Resolver struct {
	dialer          netapi.Proxy
	bootstrapConfig *pd.Dns
	store           syncmap.SyncMap[string, *Entry]
	resolvers       syncmap.SyncMap[string, *pd.Dns]
}

func NewResolver(dd netapi.Proxy) *Resolver {
	dialer.InternetResolver, _ = dns.New(dns.Config{
		Type:   pd.Type_udp,
		Host:   "8.8.8.8:53",
		Name:   "internet",
		Dialer: dr.Default,
	})
	return &Resolver{
		dialer: dd,
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
		config, ok := r.resolvers.Load(str)
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

func (r *Resolver) Apply(name string, config *pd.Dns) {
	if name == "" {
		log.Warn("resolver name is empty")
		return
	}

	ndns, ok := r.store.Load(name)
	if ok && !proto.Equal(ndns.Config, config) {
		r.store.Delete(name)
		if err := ndns.Resolver.Close(); err != nil {
			log.Error("close dns resolver failed", "key", name, "err", err)
		}
	}

	r.resolvers.Store(name, config)
}

func (r *Resolver) Delete(name string) {
	r.resolvers.Delete(name)
	ndns, ok := r.store.Load(name)
	if !ok {
		return
	}

	if err := ndns.Resolver.Close(); err != nil {
		log.Error("close dns resolver failed", "key", name, "err", err)
	}
}

func (r *Resolver) ApplyBootstrap(c *pd.Dns) {
	log.Debug("apply bootstrap dns", "config", c)

	if !proto.Equal(r.bootstrapConfig, c) {
		dd := &dnsDialer{
			Proxy: r.dialer,
			addr: func(ctx context.Context, addr netapi.Address) {
				store := netapi.GetContext(ctx)
				store.ForceMode = bypass.Mode_direct
				store.Component = "Resolver BOOTSTRAP"
				store.Resolver.ResolverSelf = dialer.InternetResolver
			},
		}
		z, err := newDNS("BOOTSTRAP", c, dd, r)
		if err != nil {
			log.Error("get bootstrap dns failed", "err", err)
		} else {
			old := dialer.Bootstrap
			dialer.Bootstrap = z
			old.Close()
			r.bootstrapConfig = c
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
		if configuration.IPv6.Load() {
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

type ResolverControl struct {
	s config.DB
	gc.UnimplementedResolverServer

	hosts   *Hosts
	fakedns *Fakedns
	r       *Resolver
}

func NewResolverControl(s config.DB, hosts *Hosts, fakedns *Fakedns, r *Resolver) *ResolverControl {
	r2 := &ResolverControl{s: s, hosts: hosts, fakedns: fakedns, r: r}

	err := s.View(func(s *config.Setting) error {
		for k, v := range s.Dns.Resolver {
			if k == "bootstrap" {
				r2.r.ApplyBootstrap(v)
			}

			r2.r.Apply(k, v)
		}

		r2.hosts.Apply(s.Dns.Hosts)

		r2.fakedns.Apply(toFakednsConfig(s))
		return nil
	})
	if err != nil {
		log.Error("init resolver failed", "err", err)
	}

	return r2
}

func (r *ResolverControl) List(ctx context.Context, req *emptypb.Empty) (*gc.ResolveList, error) {
	resp := &gc.ResolveList{}
	err := r.s.View(func(s *config.Setting) error {
		for k := range s.Dns.Resolver {
			resp.Names = append(resp.Names, k)
		}
		return nil
	})
	return resp, err
}

func (r *ResolverControl) Get(ctx context.Context, req *wrapperspb.StringValue) (*cd.Dns, error) {
	var dns *cd.Dns
	err := r.s.View(func(s *config.Setting) error {
		dns = s.Dns.Resolver[req.GetValue()]
		return nil
	})
	if err != nil {
		return nil, err
	}

	if dns == nil {
		return nil, fmt.Errorf("resolver [%s] is not exist", req.GetValue())
	}

	return dns, nil
}

func (r *ResolverControl) Save(ctx context.Context, req *gc.SaveResolver) (*cd.Dns, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("name is empty")
	}

	err := r.s.Batch(func(s *config.Setting) error {
		s.Dns.Resolver[req.Name] = req.Resolver
		return nil
	})
	if err != nil {
		return nil, err
	}

	if req.Name == "bootstrap" {
		r.r.ApplyBootstrap(req.Resolver)
	}

	r.r.Apply(req.Name, req.Resolver)

	return req.Resolver, err
}

func (r *ResolverControl) Remove(ctx context.Context, req *wrapperspb.StringValue) (*emptypb.Empty, error) {
	if req.Value == "bootstrap" {
		return &emptypb.Empty{}, nil
	}

	err := r.s.Batch(func(s *config.Setting) error {
		delete(s.Dns.Resolver, req.Value)
		return nil
	})

	r.r.Delete(req.Value)

	return &emptypb.Empty{}, err
}

func (r *ResolverControl) Hosts(ctx context.Context, _ *emptypb.Empty) (*gc.Hosts, error) {
	hosts := map[string]string{}
	err := r.s.View(func(s *config.Setting) error {
		hosts = s.Dns.Hosts
		return nil
	})

	return &gc.Hosts{Hosts: hosts}, err
}

func (r *ResolverControl) SaveHosts(ctx context.Context, req *gc.Hosts) (*emptypb.Empty, error) {
	err := r.s.Batch(func(s *config.Setting) error {
		s.Dns.Hosts = req.Hosts
		return nil
	})
	if err != nil {
		return nil, err
	}

	r.hosts.Apply(req.Hosts)

	return &emptypb.Empty{}, nil
}

func toFakednsConfig(s *config.Setting) *cd.FakednsConfig {
	return &cd.FakednsConfig{
		Enabled:   s.Dns.Fakedns,
		Ipv4Range: s.Dns.FakednsIpRange,
		Ipv6Range: s.Dns.FakednsIpv6Range,
		Whitelist: s.Dns.FakednsWhitelist,
	}
}

func (r *ResolverControl) Fakedns(context.Context, *emptypb.Empty) (*cd.FakednsConfig, error) {
	var c *cd.FakednsConfig
	err := r.s.View(func(s *config.Setting) error {
		c = toFakednsConfig(s)
		return nil
	})
	return c, err
}

func (r *ResolverControl) SaveFakedns(ctx context.Context, req *cd.FakednsConfig) (*emptypb.Empty, error) {
	err := r.s.Batch(func(s *config.Setting) error {
		s.Dns.Fakedns = req.Enabled
		s.Dns.FakednsIpRange = req.Ipv4Range
		s.Dns.FakednsIpv6Range = req.Ipv6Range
		s.Dns.FakednsWhitelist = req.Whitelist
		return nil
	})
	if err != nil {
		return nil, err
	}

	r.fakedns.Apply(req)

	return &emptypb.Empty{}, err
}

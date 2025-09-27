package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/miekg/dns"
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
	mu              sync.RWMutex
	bootstrapMu     sync.Mutex
}

func NewResolver(dd netapi.Proxy) *Resolver {
	return &Resolver{
		dialer: dd,
	}
}

var errorResolver = netapi.ErrorResolver(func(domain string) error {
	return &net.OpError{
		Op: "block",
		Addr: netapi.DomainAddr{
			HostnameX: domain,
		},
		Err: errors.New("blocked"),
	}
})

var block = bypass.Mode_block.String()

func (r *Resolver) getFallbackResolver(str, fallback string) netapi.Resolver {
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
		return z
	}

	return dialer.Bootstrap()
}

func (r *Resolver) Close() error {
	for _, v := range r.store.Range {
		v.Resolver.Close()
	}

	r.store = syncmap.SyncMap[string, *Entry]{}

	return nil
}

func (r *Resolver) getResolver(str string) (netapi.Resolver, bool) {
	if str == "bootstrap" {
		return dialer.Bootstrap(), true
	}

	e, ok := r.store.Load(str)
	if ok {
		return e.Resolver, true
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
				store.SetComponent("Resolver " + str)
				// force to use bootstrap dns, otherwise will dns query cycle
				store.ConnOptions().Resolver().SetResolverResolver(dialer.Bootstrap())
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

	return e.Resolver, err == nil
}

func (r *Resolver) Apply(name string, config *pd.Dns) {
	if name == "" {
		log.Warn("resolver name is empty")
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

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
	r.mu.Lock()
	defer r.mu.Unlock()

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
	r.bootstrapMu.Lock()
	defer r.bootstrapMu.Unlock()

	log.Debug("apply bootstrap dns", "config", c)

	if !proto.Equal(r.bootstrapConfig, c) {
		dd := &dnsDialer{
			Proxy: r.dialer,
			addr: func(ctx context.Context, addr netapi.Address) {
				store := netapi.GetContext(ctx)
				store.ConnOptions().SetForceMode(bypass.Mode_direct)
				store.SetComponent("Resolver BOOTSTRAP")
				store.ConnOptions().Resolver().SetResolverResolver(resolver.Internet)
			},
		}
		z, err := newDNS("BOOTSTRAP", c, dd, r)
		if err != nil {
			log.Error("get bootstrap dns failed", "err", err)
		} else {
			dialer.SetBootstrap(z)
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

func (d *dnsWrap) LookupIP(ctx context.Context, host string, opts ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
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

func (d *dnsWrap) Raw(ctx context.Context, req dns.Question) (dns.Msg, error) {
	msg, err := d.dns.Raw(ctx, req)
	if err != nil {
		return dns.Msg{}, fmt.Errorf("[%s] do raw dns request failed: %w", d.name, err)
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
	subnet, err := netip.ParsePrefix(dc.GetSubnet())
	if err != nil {
		p, err := netip.ParseAddr(dc.GetSubnet())
		if err == nil {
			subnet = netip.PrefixFrom(p, p.BitLen())
		}
	}
	r, err := resolver.New(
		resolver.Config{
			Type:       dc.GetType(),
			Name:       name,
			Host:       dc.GetHost(),
			Servername: dc.GetTlsServername(),
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

type ResolverCtr struct {
	s config.DB
	gc.UnimplementedResolverServer

	hosts     *Hosts
	fakedns   *Fakedns
	r         *Resolver
	dnsServer *DnsServer
}

func NewResolverCtr(s config.DB, hosts *Hosts, fakedns *Fakedns, r *Resolver, server *DnsServer) *ResolverCtr {
	r2 := &ResolverCtr{s: s, hosts: hosts, fakedns: fakedns, r: r, dnsServer: server}

	err := s.View(func(s *config.Setting) error {
		for k, v := range s.GetDns().GetResolver() {
			if k == "bootstrap" {
				r2.r.ApplyBootstrap(v)
			}

			r2.r.Apply(k, v)
		}

		r2.hosts.Apply(s.GetDns().GetHosts())

		r2.fakedns.Apply(toFakednsConfig(s))
		r2.dnsServer.SetServer(s.GetDns().GetServer())
		return nil
	})
	if err != nil {
		log.Error("init resolver failed", "err", err)
	}

	return r2
}

func (r *ResolverCtr) List(ctx context.Context, req *emptypb.Empty) (*gc.ResolveList, error) {
	resp := &gc.ResolveList{}
	err := r.s.View(func(s *config.Setting) error {
		for k := range s.GetDns().GetResolver() {
			resp.SetNames(append(resp.GetNames(), k))
		}
		return nil
	})
	return resp, err
}

func (r *ResolverCtr) Get(ctx context.Context, req *wrapperspb.StringValue) (*pd.Dns, error) {
	var dns *pd.Dns
	err := r.s.View(func(s *config.Setting) error {
		dns = s.GetDns().GetResolver()[req.GetValue()]
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

func (r *ResolverCtr) Save(ctx context.Context, req *gc.SaveResolver) (*pd.Dns, error) {
	if req.GetName() == "" {
		return nil, fmt.Errorf("name is empty")
	}

	err := r.s.Batch(func(s *config.Setting) error {
		s.GetDns().GetResolver()[req.GetName()] = req.GetResolver()
		return nil
	})
	if err != nil {
		return nil, err
	}

	if req.GetName() == "bootstrap" {
		r.r.ApplyBootstrap(req.GetResolver())
	}

	r.r.Apply(req.GetName(), req.GetResolver())

	return req.GetResolver(), err
}

func (r *ResolverCtr) Remove(ctx context.Context, req *wrapperspb.StringValue) (*emptypb.Empty, error) {
	if req.Value == "bootstrap" {
		return &emptypb.Empty{}, nil
	}

	err := r.s.Batch(func(s *config.Setting) error {
		delete(s.GetDns().GetResolver(), req.Value)
		return nil
	})

	r.r.Delete(req.Value)

	return &emptypb.Empty{}, err
}

func (r *ResolverCtr) Hosts(ctx context.Context, _ *emptypb.Empty) (*gc.Hosts, error) {
	hosts := map[string]string{}
	err := r.s.View(func(s *config.Setting) error {
		hosts = s.GetDns().GetHosts()
		return nil
	})

	return (&gc.Hosts_builder{Hosts: hosts}).Build(), err
}

func (r *ResolverCtr) SaveHosts(ctx context.Context, req *gc.Hosts) (*emptypb.Empty, error) {
	err := r.s.Batch(func(s *config.Setting) error {
		s.GetDns().SetHosts(req.GetHosts())
		return nil
	})
	if err != nil {
		return nil, err
	}

	r.hosts.Apply(req.GetHosts())

	return &emptypb.Empty{}, nil
}

func toFakednsConfig(s *config.Setting) *pd.FakednsConfig {
	return (&pd.FakednsConfig_builder{
		Enabled:       proto.Bool(s.GetDns().GetFakedns()),
		Ipv4Range:     proto.String(s.GetDns().GetFakednsIpRange()),
		Ipv6Range:     proto.String(s.GetDns().GetFakednsIpv6Range()),
		Whitelist:     s.GetDns().GetFakednsWhitelist(),
		SkipCheckList: s.GetDns().GetFakednsSkipCheckList(),
	}).Build()
}

func (r *ResolverCtr) Fakedns(context.Context, *emptypb.Empty) (*pd.FakednsConfig, error) {
	var c *pd.FakednsConfig
	err := r.s.View(func(s *config.Setting) error {
		c = toFakednsConfig(s)
		return nil
	})
	return c, err
}

func (r *ResolverCtr) SaveFakedns(ctx context.Context, req *pd.FakednsConfig) (*emptypb.Empty, error) {
	err := r.s.Batch(func(s *config.Setting) error {
		s.GetDns().SetFakedns(req.GetEnabled())
		s.GetDns().SetFakednsIpRange(req.GetIpv4Range())
		s.GetDns().SetFakednsIpv6Range(req.GetIpv6Range())
		s.GetDns().SetFakednsWhitelist(req.GetWhitelist())
		s.GetDns().SetFakednsSkipCheckList(req.GetSkipCheckList())
		return nil
	})
	if err != nil {
		return nil, err
	}

	r.fakedns.Apply(req)

	return &emptypb.Empty{}, err
}

func (r *ResolverCtr) Server(context.Context, *emptypb.Empty) (*wrapperspb.StringValue, error) {
	var server string
	err := r.s.View(func(s *config.Setting) error {
		server = s.GetDns().GetServer()
		return nil
	})
	return &wrapperspb.StringValue{Value: server}, err
}

func (r *ResolverCtr) SaveServer(ctx context.Context, req *wrapperspb.StringValue) (*emptypb.Empty, error) {
	err := r.s.Batch(func(s *config.Setting) error {
		s.GetDns().SetServer(req.Value)
		r.dnsServer.SetServer(req.Value)
		return nil
	})
	return &emptypb.Empty{}, err
}

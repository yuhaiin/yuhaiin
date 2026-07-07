package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/chore"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/paging"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"slices"
)

type Entry struct {
	Resolver netapi.Resolver
	Config   *config.Dns
}

type Resolver struct {
	dialer          netapi.Proxy
	bootstrapConfig *config.Dns
	store           syncmap.SyncMap[string, *Entry]
	resolvers       syncmap.SyncMap[string, *config.Dns]
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

var block = config.Mode_block.String()

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

	return netapi.Bootstrap()
}

func (r *Resolver) Close() error {
	for _, v := range r.store.Range {
		v.Resolver.Close()
	}

	r.store.Clear()
	return nil
}

func (r *Resolver) getResolver(name string) (netapi.Resolver, bool) {
	if name == "bootstrap" {
		return netapi.Bootstrap(), true
	}

	e, ok := r.store.Load(name)
	if ok {
		return e.Resolver, true
	}

	e, _, err := r.store.LoadOrCreate(name, func() (*Entry, error) {
		config, ok := r.resolvers.Load(name)
		if !ok {
			return nil, fmt.Errorf("resolver %s not found", name)
		}

		dialer := &dnsDialer{
			Proxy:    r.dialer,
			resolver: netapi.Bootstrap,
			name:     name,
		}

		z, err := newResolver(name, config, dialer)
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

func (r *Resolver) Apply(name string, config *config.Dns) {
	if name == "" {
		log.Warn("resolver name is empty")
		return
	}

	var old netapi.Resolver
	r.mu.Lock()
	ndns, ok := r.store.Load(name)
	if ok && !proto.Equal(ndns.Config, config) {
		r.store.Delete(name)
		old = ndns.Resolver
	}

	r.resolvers.Store(name, config)
	r.mu.Unlock()

	if old != nil {
		if err := old.Close(); err != nil {
			log.Error("close dns resolver failed", "key", name, "err", err)
		}
	}
}

func (r *Resolver) Delete(name string) {
	var old netapi.Resolver
	r.mu.Lock()
	r.resolvers.Delete(name)
	ndns, ok := r.store.Load(name)
	if ok {
		r.store.Delete(name)
		old = ndns.Resolver
	}
	r.mu.Unlock()

	if old != nil {
		if err := old.Close(); err != nil {
			log.Error("close dns resolver failed", "key", name, "err", err)
		}
	}
}

func (r *Resolver) ApplyBootstrap(c *config.Dns) {
	if c == nil {
		return
	}

	r.bootstrapMu.Lock()
	if proto.Equal(r.bootstrapConfig, c) {
		r.bootstrapMu.Unlock()
		return
	}
	nextConfig := proto.Clone(c).(*config.Dns)
	r.bootstrapMu.Unlock()

	log.Debug("apply bootstrap dns", "config", c)

	dd := &dnsDialer{
		Proxy:     r.dialer,
		resolver:  func() netapi.Resolver { return resolver.Internet },
		name:      "bootstrap",
		bootstrap: true,
	}
	z, err := newResolver("bootstrap", nextConfig, dd)
	if err != nil {
		log.Error("new bootstrap dns failed", "err", err)
		return
	}
	netapi.SetBootstrap(z)

	r.bootstrapMu.Lock()
	r.bootstrapConfig = nextConfig
	r.bootstrapMu.Unlock()
}

type dnsWrap struct{ netapi.Resolver }

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

	ips, err := d.Resolver.LookupIP(ctx, host, opt)
	if err != nil {
		return nil, fmt.Errorf("[%s] lookup failed: %w", d.Name(), err)
	}

	return ips, nil
}

func (d *dnsWrap) Raw(ctx context.Context, req dns.Question) (dns.Msg, error) {
	msg, err := d.Resolver.Raw(ctx, req)
	if err != nil {
		return dns.Msg{}, fmt.Errorf("[%s] do raw dns request failed: %w", d.Name(), err)
	}

	return msg, nil
}

func newResolver(name string, dc *config.Dns, dialer netapi.Proxy) (netapi.Resolver, error) {
	subnet, err := netip.ParsePrefix(dc.GetSubnet())
	if err != nil {
		p, err := netip.ParseAddr(dc.GetSubnet())
		if err == nil {
			subnet = netip.PrefixFrom(p, p.BitLen())
		}
	}

	config := resolver.Config{
		Type:       dc.GetType(),
		Name:       name,
		Host:       dc.GetHost(),
		Servername: dc.GetTlsServername(),
		Subnet:     subnet,
		Dialer:     dialer,
	}

	r, err := resolver.New(config)
	if err != nil {
		return nil, err
	}

	return &dnsWrap{r}, nil
}

type dnsDialer struct {
	netapi.Proxy
	resolver  func() netapi.Resolver
	name      string
	bootstrap bool
}

func (d *dnsDialer) newCtx(c context.Context) *netapi.Context {
	ctx := netapi.WithContext(c)
	if d.bootstrap {
		ctx.ConnOptions().SetRouteMode(config.Mode_direct)
	}
	ctx.SetComponent(fmt.Sprintf("dns:%s", d.name)).
		ConnOptions().Resolver().SetResolver(d.resolver()).SetIsResolver()
	return ctx
}

func (d *dnsDialer) Conn(c context.Context, addr netapi.Address) (net.Conn, error) {
	return d.Proxy.Conn(d.newCtx(c), addr)
}

func (d *dnsDialer) PacketConn(c context.Context, addr netapi.Address) (net.PacketConn, error) {
	return d.Proxy.PacketConn(d.newCtx(c), addr)
}

type ResolverCtr struct {
	s chore.DB
	api.UnimplementedResolverServer

	hosts   *Hosts
	fakedns *Fakedns
	r       *Resolver
}

func NewResolverCtr(s chore.DB, hosts *Hosts, fakedns *Fakedns, r *Resolver) *ResolverCtr {
	r2 := &ResolverCtr{s: s, hosts: hosts, fakedns: fakedns, r: r}

	var setting *config.Setting
	err := s.View(func(s *config.Setting) error {
		setting = proto.Clone(s).(*config.Setting)
		return nil
	})
	if err != nil {
		log.Error("init resolver failed", "err", err)
		return r2
	}

	r2.ApplySetting(setting)
	return r2
}

func (r *ResolverCtr) ApplySetting(s *config.Setting) {
	if s == nil {
		return
	}

	log.Info("apply resolver setting")
	for k, v := range s.GetDns().GetResolver() {
		if k == "bootstrap" {
			log.Info("apply bootstrap resolver")
			r.r.ApplyBootstrap(v)
		}

		r.r.Apply(k, v)
	}

	log.Info("apply hosts setting")
	r.hosts.Apply(s.GetDns().GetHosts())
	log.Info("apply fakedns setting")
	r.fakedns.Apply(toFakednsConfig(s))
	log.Info("apply fakedns server")
	r.fakedns.SetServer(s.GetDns().GetServer())
	log.Info("apply resolver setting finished")
}

func (r *ResolverCtr) List(ctx context.Context, req *emptypb.Empty) (*api.ResolveList, error) {
	resp := &api.ResolveList{}
	err := r.s.View(func(s *config.Setting) error {
		items := make([]*api.ResolverItem, 0, len(s.GetDns().GetResolver()))
		for k, resolver := range s.GetDns().GetResolver() {
			resp.SetNames(append(resp.GetNames(), k))
			items = append(items, resolverItem(k, resolver))
		}
		resp.SetItems(items)
		return nil
	})
	return resp, err
}

func resolverItem(name string, resolver *config.Dns) *api.ResolverItem {
	system := name == "bootstrap"
	host := resolver.GetHost()
	if system && host == "" {
		host = "system default"
	}

	return api.ResolverItem_builder{
		Name:          new(name),
		Type:          new(resolver.GetType().String()),
		Host:          new(host),
		Subnet:        new(resolver.GetSubnet()),
		TlsServername: new(resolver.GetTlsServername()),
		System:        new(system),
	}.Build()
}

func (r *ResolverCtr) ListPage(ctx context.Context, req *api.PageRequest) (*api.ResolveList, error) {
	resp, err := r.List(ctx, &emptypb.Empty{})
	if err != nil {
		return resp, err
	}

	items := resp.GetItems()
	slices.SortFunc(items, func(a, b *api.ResolverItem) int { return strings.Compare(a.GetName(), b.GetName()) })
	items = paging.Filter(items, req.GetQuery(), func(item *api.ResolverItem, query string) bool {
		return paging.MatchString(item.GetName(), query) ||
			paging.MatchString(item.GetType(), query) ||
			paging.MatchString(item.GetHost(), query)
	})
	pageItems, page, pageSize, total := paging.Slice(items, req.GetPage(), req.GetPageSize())
	pageNames := make([]string, 0, len(pageItems))
	for _, item := range pageItems {
		pageNames = append(pageNames, item.GetName())
	}
	resp.SetNames(pageNames)
	resp.SetItems(pageItems)
	resp.SetPage(api.PageResponse_builder{
		Page:     new(page),
		PageSize: new(pageSize),
		Total:    new(total),
	}.Build())
	return resp, nil
}

func (r *ResolverCtr) Get(ctx context.Context, req *wrapperspb.StringValue) (*config.Dns, error) {
	var dns *config.Dns
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

func (r *ResolverCtr) Save(ctx context.Context, req *api.SaveResolver) (*config.Dns, error) {
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

func (r *ResolverCtr) Hosts(ctx context.Context, _ *emptypb.Empty) (*api.Hosts, error) {
	hosts := map[string]string{}
	err := r.s.View(func(s *config.Setting) error {
		hosts = s.GetDns().GetHosts()
		return nil
	})

	return (&api.Hosts_builder{Hosts: hosts}).Build(), err
}

func (r *ResolverCtr) SaveHosts(ctx context.Context, req *api.Hosts) (*emptypb.Empty, error) {
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

func toFakednsConfig(s *config.Setting) *config.FakednsConfig {
	return (&config.FakednsConfig_builder{
		Enabled:       new(s.GetDns().GetFakedns()),
		Ipv4Range:     new(s.GetDns().GetFakednsIpRange()),
		Ipv6Range:     new(s.GetDns().GetFakednsIpv6Range()),
		Whitelist:     s.GetDns().GetFakednsWhitelist(),
		SkipCheckList: s.GetDns().GetFakednsSkipCheckList(),
	}).Build()
}

func FakednsConfigFromSetting(s *config.Setting) *config.FakednsConfig {
	if s == nil {
		return nil
	}
	return toFakednsConfig(s)
}

func (r *ResolverCtr) Fakedns(context.Context, *emptypb.Empty) (*config.FakednsConfig, error) {
	var c *config.FakednsConfig
	err := r.s.View(func(s *config.Setting) error {
		c = toFakednsConfig(s)
		return nil
	})
	return c, err
}

func (r *ResolverCtr) SaveFakedns(ctx context.Context, req *config.FakednsConfig) (*emptypb.Empty, error) {
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
		r.fakedns.SetServer(req.Value)
		return nil
	})
	return &emptypb.Empty{}, err
}

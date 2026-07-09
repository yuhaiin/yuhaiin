package resolver

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/miekg/dns"
)

type Entry struct {
	Resolver netapi.Resolver
	Config   contractresolver.Resolver
}

type Resolver struct {
	dialer          netapi.Proxy
	bootstrapConfig contractresolver.Resolver
	store           syncmap.SyncMap[string, *Entry]
	resolvers       syncmap.SyncMap[string, contractresolver.Resolver]
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

const block = "block"

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

		z, err := newContractResolver(config, dialer)
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

func (r *Resolver) Apply(config contractresolver.Resolver) {
	name := config.ID
	if name == "" {
		log.Warn("resolver name is empty")
		return
	}

	var old netapi.Resolver
	r.mu.Lock()
	ndns, ok := r.store.Load(name)
	if ok && !reflect.DeepEqual(ndns.Config, config) {
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

func (r *Resolver) ApplyBootstrap(c contractresolver.Resolver) {
	if c.ID == "" {
		return
	}

	r.bootstrapMu.Lock()
	if reflect.DeepEqual(r.bootstrapConfig, c) {
		r.bootstrapMu.Unlock()
		return
	}
	nextConfig := cloneContractResolver(c)
	r.bootstrapMu.Unlock()

	log.Debug("apply bootstrap dns", "config", c)

	dd := &dnsDialer{
		Proxy:     r.dialer,
		resolver:  func() netapi.Resolver { return resolver.Internet },
		name:      "bootstrap",
		bootstrap: true,
	}
	z, err := newContractResolver(nextConfig, dd)
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

func newContractResolver(dc contractresolver.Resolver, dialer netapi.Proxy) (netapi.Resolver, error) {
	subnet, err := netip.ParsePrefix(dc.Subnet)
	if err != nil {
		p, err := netip.ParseAddr(dc.Subnet)
		if err == nil {
			subnet = netip.PrefixFrom(p, p.BitLen())
		}
	}

	config := resolver.Config{
		Type:       dc.Type,
		Name:       dc.ID,
		Host:       dc.Host,
		Servername: dc.TLSServerName,
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
		ctx.ConnOptions().SetRouteMode("direct")
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
	resolvers ResolverBook
	config    ResolverConfigBook

	hosts   *Hosts
	fakedns *Fakedns
	r       *Resolver
}

type ResolverBook interface {
	List(context.Context) ([]contractresolver.Resolver, error)
	Save(context.Context, contractresolver.Resolver, int64) error
	Delete(context.Context, string) error
}

type ResolverConfigBook interface {
	Hosts(context.Context) (contractresolver.Hosts, error)
	SaveHosts(context.Context, contractresolver.Hosts) (contractresolver.Hosts, error)
	FakeDNS(context.Context) (contractresolver.FakeDNS, error)
	SaveFakeDNS(context.Context, contractresolver.FakeDNS) (contractresolver.FakeDNS, error)
	Server(context.Context) (contractresolver.Server, error)
	SaveServer(context.Context, contractresolver.Server) (contractresolver.Server, error)
}

func NewResolverCtr(resolvers ResolverBook, config ResolverConfigBook, hosts *Hosts, fakedns *Fakedns, r *Resolver) *ResolverCtr {
	r2 := &ResolverCtr{resolvers: resolvers, config: config, hosts: hosts, fakedns: fakedns, r: r}
	r2.ApplyStored(context.Background())
	return r2
}

func cloneContractResolver(src contractresolver.Resolver) contractresolver.Resolver {
	dst := contractresolver.Resolver{}
	if data, err := json.Marshal(src); err == nil {
		if err := json.Unmarshal(data, &dst); err == nil {
			return dst
		}
	}
	return src
}

func (r *ResolverCtr) ApplyStored(ctx context.Context) {
	if r == nil {
		return
	}

	log.Info("apply resolver setting")
	if r.resolvers != nil {
		resolvers, err := r.resolvers.List(ctx)
		if err != nil {
			log.Error("init resolver failed", "err", err)
		} else {
			for _, item := range resolvers {
				if item.ID == "bootstrap" {
					log.Info("apply bootstrap resolver")
					r.r.ApplyBootstrap(item)
				}
				r.r.Apply(item)
			}
		}
	}

	if r.config != nil {
		log.Info("apply hosts setting")
		hosts, err := r.config.Hosts(ctx)
		if err != nil {
			log.Warn("load resolver hosts failed", "err", err)
		} else {
			r.hosts.Apply(hosts.Hosts)
		}

		log.Info("apply fakedns setting")
		fakedns, err := r.config.FakeDNS(ctx)
		if err != nil {
			log.Warn("load fakedns setting failed", "err", err)
		} else {
			r.fakedns.Apply(fakedns)
		}

		log.Info("apply fakedns server")
		server, err := r.config.Server(ctx)
		if err != nil {
			log.Warn("load dns server failed", "err", err)
		} else {
			r.fakedns.SetServer(server.Server)
		}
	}
	log.Info("apply resolver setting finished")
}

func (r *ResolverCtr) SaveContract(ctx context.Context, req contractresolver.Resolver) (contractresolver.Resolver, error) {
	if req.ID == "" {
		return contractresolver.Resolver{}, fmt.Errorf("name is empty")
	}
	if err := req.Validate(); err != nil {
		return contractresolver.Resolver{}, err
	}

	if r.resolvers == nil {
		return contractresolver.Resolver{}, errors.New("resolver store is unavailable")
	}
	if err := r.resolvers.Save(ctx, req, 0); err != nil {
		return contractresolver.Resolver{}, err
	}

	if req.ID == "bootstrap" {
		r.r.ApplyBootstrap(req)
	}

	r.r.Apply(req)

	return req, nil
}

func (r *ResolverCtr) RemoveContract(ctx context.Context, id string) error {
	if id == "bootstrap" {
		return nil
	}
	if r.resolvers == nil {
		return errors.New("resolver store is unavailable")
	}
	err := r.resolvers.Delete(ctx, id)

	r.r.Delete(id)

	return err
}

func (r *ResolverCtr) ContractHosts(ctx context.Context) (contractresolver.Hosts, error) {
	if r.config == nil {
		return contractresolver.Hosts{}, errors.New("resolver config store is unavailable")
	}
	return r.config.Hosts(ctx)
}

func (r *ResolverCtr) SaveContractHosts(ctx context.Context, req contractresolver.Hosts) (contractresolver.Hosts, error) {
	if req.Hosts == nil {
		req.Hosts = map[string]string{}
	}
	if r.config == nil {
		return contractresolver.Hosts{}, errors.New("resolver config store is unavailable")
	}
	req, err := r.config.SaveHosts(ctx, req)
	if err != nil {
		return contractresolver.Hosts{}, err
	}

	r.hosts.Apply(req.Hosts)

	return req, nil
}

func (r *ResolverCtr) ContractFakedns(ctx context.Context) (contractresolver.FakeDNS, error) {
	if r.config == nil {
		return contractresolver.FakeDNS{}, errors.New("resolver config store is unavailable")
	}
	return r.config.FakeDNS(ctx)
}

func (r *ResolverCtr) SaveContractFakedns(ctx context.Context, req contractresolver.FakeDNS) (contractresolver.FakeDNS, error) {
	if r.config == nil {
		return contractresolver.FakeDNS{}, errors.New("resolver config store is unavailable")
	}
	req, err := r.config.SaveFakeDNS(ctx, req)
	if err != nil {
		return contractresolver.FakeDNS{}, err
	}

	r.fakedns.Apply(req)

	return req, err
}

func (r *ResolverCtr) ContractServer(ctx context.Context) (contractresolver.Server, error) {
	if r.config == nil {
		return contractresolver.Server{}, errors.New("resolver config store is unavailable")
	}
	return r.config.Server(ctx)
}

func (r *ResolverCtr) SaveContractServer(ctx context.Context, req contractresolver.Server) (contractresolver.Server, error) {
	if r.config == nil {
		return contractresolver.Server{}, errors.New("resolver config store is unavailable")
	}
	req, err := r.config.SaveServer(ctx, req)
	r.fakedns.SetServer(req.Server)
	return req, err
}

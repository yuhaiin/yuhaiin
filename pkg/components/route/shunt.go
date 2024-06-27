package route

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"golang.org/x/net/dns/dnsmessage"
)

type routeTries struct {
	trie        *trie.Trie[bypass.ModeEnum]
	processTrie map[string]bypass.ModeEnum
	tags        []string
}

func newRouteTires() *routeTries {
	return &routeTries{
		trie:        trie.NewTrie[bypass.ModeEnum](),
		processTrie: make(map[string]bypass.ModeEnum),
		tags:        []string{},
	}
}

type Route struct {
	resolveDomain bool
	modifiedTime  int64

	customTrie *routeTries
	trie       *routeTries

	config        *bypass.BypassConfig
	ProcessDumper netapi.ProcessDumper

	mu sync.RWMutex

	r Resolver
	d Dialer
}

type Resolver interface {
	Get(str string) netapi.Resolver
}
type Dialer interface {
	Get(ctx context.Context, network string, str string, tag string) (netapi.Proxy, error)
}

func NewRoute(d Dialer, r Resolver, ProcessDumper netapi.ProcessDumper) *Route {
	return &Route{
		trie:       newRouteTires(),
		customTrie: newRouteTires(),
		config: &bypass.BypassConfig{
			Tcp: bypass.Mode_bypass,
			Udp: bypass.Mode_bypass,
		},
		r:             r,
		d:             d,
		ProcessDumper: ProcessDumper,
	}
}

func (s *Route) Tags() []string { return append(s.trie.tags, s.customTrie.tags...) }

func (s *Route) Conn(ctx context.Context, host netapi.Address) (net.Conn, error) {
	mode, host := s.dispatch(ctx, s.config.Tcp, host)

	p, err := s.d.Get(ctx, "tcp", mode.Mode().String(), mode.GetTag())
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	conn, err := p.Conn(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	return conn, nil
}

func (s *Route) PacketConn(ctx context.Context, host netapi.Address) (net.PacketConn, error) {
	mode, host := s.dispatch(ctx, s.config.Udp, host)

	p, err := s.d.Get(ctx, "udp", mode.Mode().String(), mode.GetTag())
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	conn, err := p.PacketConn(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	return conn, nil
}

func (s *Route) Dispatch(ctx context.Context, host netapi.Address) (netapi.Address, error) {
	_, addr := s.dispatch(ctx, bypass.Mode_bypass, host)
	return addr, nil
}

func (s *Route) Search(ctx context.Context, addr netapi.Address) bypass.ModeEnum {
	mode, ok := s.customTrie.trie.Search(ctx, addr)
	if ok {
		return mode
	}

	mode, ok = s.trie.trie.Search(ctx, addr)
	if ok {
		return mode
	}

	return bypass.Mode_proxy
}

func (s *Route) dispatch(ctx context.Context, networkMode bypass.Mode, host netapi.Address) (bypass.ModeEnum, netapi.Address) {
	var mode bypass.ModeEnum = bypass.Mode_bypass

	process := s.DumpProcess(ctx, host)
	if process != "" {
		matchProcess := strings.TrimSuffix(process, " (deleted)")
		for _, v := range []map[string]bypass.ModeEnum{
			s.customTrie.processTrie,
			s.trie.processTrie,
		} {
			if m, ok := v[matchProcess]; ok {
				mode = m
				break
			}
		}
	}

	// get mode from upstream specified
	store := netapi.GetContext(ctx)

	if mode.Mode() == bypass.Mode_bypass {
		if bypass.Mode(store.ForceMode) != bypass.Mode_bypass {
			mode = bypass.Mode(store.ForceMode)
		} else {
			mode = networkMode // get mode from network(tcp/udp) rule
		}
	}

	if mode.Mode() == bypass.Mode_bypass {
		// get mode from bypass rule
		store.Resolver.Resolver = s.r.Get("")
		mode = s.Search(ctx, host)
		store.Resolver.PreferIPv6 = mode.GetResolveStrategy() == bypass.ResolveStrategy_prefer_ipv6
	}

	store.Resolver.SkipResolve = s.skipResolve(mode)
	store.Mode = mode.Mode()
	store.Resolver.Resolver = s.r.Get(mode.Mode().String())

	if s.resolveDomain && host.IsFqdn() && mode == bypass.Mode_proxy {
		// resolve proxy domain if resolveRemoteDomain enabled
		ip, err := netapi.ResolverIP(ctx, host)
		if err == nil {
			store.DomainString = host.String()
			host = netapi.ParseIPAddrPort(host.Network(), ip, host.Port())
			store.IPString = host.String()
		} else {
			log.Warn("resolve remote domain failed", "err", err)
		}
	}

	return mode, host
}

func (s *Route) skipResolve(mode bypass.ModeEnum) bool {
	if mode.Mode() != bypass.Mode_proxy {
		return false
	}

	switch s.config.GetUdpProxyFqdn() {
	case bypass.UdpProxyFqdnStrategy_skip_resolve:
		return mode.UdpProxyFqdn() != bypass.UdpProxyFqdnStrategy_resolve
	default:
		return mode.UdpProxyFqdn() == bypass.UdpProxyFqdnStrategy_skip_resolve
	}
}

func (s *Route) Resolver(ctx context.Context, domain string) netapi.Resolver {
	host := netapi.ParseAddressPort("", domain, 0)
	netapi.GetContext(ctx).Resolver.Resolver = trie.SkipResolver
	return s.r.Get(s.Search(ctx, host).Mode().String())
}

func (f *Route) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) ([]net.IP, error) {
	return f.Resolver(ctx, domain).LookupIP(ctx, domain, opts...)
}

func (f *Route) Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	return f.Resolver(ctx, strings.TrimSuffix(req.Name.String(), ".")).Raw(ctx, req)
}

func (f *Route) Close() error { return nil }

func (c *Route) DumpProcess(ctx context.Context, addr netapi.Address) (s string) {
	if c.ProcessDumper == nil {
		return
	}

	store := netapi.GetContext(ctx)

	var dst []net.Addr
	if store.Inbound != nil {
		dst = append(dst, store.Inbound)
	}

	if store.Destination != nil {
		dst = append(dst, store.Destination)
	}

	if len(dst) == 0 {
		return
	}

	sourceAddr, err := netapi.ParseSysAddr(store.Source)
	if err != nil {
		return
	}

	for _, d := range dst {
		dst, err := netapi.ParseSysAddr(d)
		if err != nil {
			continue
		}

		process, err := c.ProcessDumper.ProcessName(addr.Network(), sourceAddr, dst)
		if err != nil {
			// log.Warn("get process name failed", "err", err)
			continue
		}

		store.Process = process
		return process
	}

	return ""
}

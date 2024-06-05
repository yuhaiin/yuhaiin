package route

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/utils/convert"
	"golang.org/x/net/dns/dnsmessage"
)

type modeMarkKey struct{}

func (modeMarkKey) String() string { return "MODE" }

type DOMAIN_MARK_KEY struct{}

type IP_MARK_KEY struct{}

func (IP_MARK_KEY) String() string { return "IP" }

type ForceModeKey struct{}

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
		for _, v := range []map[string]bypass.ModeEnum{
			s.customTrie.processTrie,
			s.trie.processTrie,
		} {
			if m, ok := v[process]; ok {
				mode = m
				break
			}
		}
	}

	// get mode from upstream specified
	store := netapi.StoreFromContext(ctx)

	if mode.Mode() == bypass.Mode_bypass {
		mode = netapi.GetDefault(
			ctx,
			ForceModeKey{},
			networkMode, // get mode from network(tcp/udp) rule
		)
	}

	if mode.Mode() == bypass.Mode_bypass {
		// get mode from bypass rule
		host.SetResolver(s.r.Get(""))
		mode = s.Search(ctx, host)
		if mode.GetResolveStrategy() == bypass.ResolveStrategy_prefer_ipv6 {
			host.PreferIPv6(true)
		}
	}

	if s.skipResolve(mode) {
		store.Add(nat.SkipResolveKey{}, true)
	}

	store.Add(modeMarkKey{}, mode.Mode())
	host.SetResolver(s.r.Get(mode.Mode().String()))

	if s.resolveDomain && host.IsFqdn() && mode == bypass.Mode_proxy {
		// resolve proxy domain if resolveRemoteDomain enabled
		ip, err := host.IP(ctx)
		if err == nil {
			store.Add(DOMAIN_MARK_KEY{}, host.String())
			host = host.OverrideHostname(ip.String())
			store.Add(IP_MARK_KEY{}, host.String())
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
	host := netapi.ParseAddressPort(0, domain, netapi.EmptyPort)
	host.SetResolver(trie.SkipResolver)
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

	store := netapi.StoreFromContext(ctx)

	source, ok := store.Get(netapi.SourceKey{})
	if !ok {
		return
	}

	var dst []any
	ds, ok := store.Get(netapi.InboundKey{})
	if ok {
		dst = append(dst, ds)
	}
	ds, ok = store.Get(netapi.DestinationKey{})
	if ok {
		dst = append(dst, ds)
	}

	if len(dst) == 0 {
		return
	}

	sourceAddr, err := convert.ToProxyAddress(addr.NetworkType(), source)
	if err != nil {
		return
	}

	for _, d := range dst {
		dst, err := convert.ToProxyAddress(addr.NetworkType(), d)
		if err != nil {
			continue
		}

		process, err := c.ProcessDumper.ProcessName(addr.Network(), sourceAddr, dst)
		if err != nil {
			// log.Warn("get process name failed", "err", err)
			continue
		}

		store.Add("Process", process)
		return process
	}

	return ""
}

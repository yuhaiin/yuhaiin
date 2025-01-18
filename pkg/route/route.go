package route

import (
	"context"
	"iter"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"golang.org/x/net/dns/dnsmessage"
)

type Route struct {
	ProcessDumper netapi.ProcessDumper

	r Resolver
	d Dialer

	customTrie *atomic.Pointer[routeTries]
	trie       *atomic.Pointer[routeTries]

	loopback LoopbackDetector
	config   *bypass.Config

	*RejectHistory

	matchers []*matcher
	mu       sync.RWMutex
}

type Resolver interface {
	Get(resolver, fallback string) netapi.Resolver
}

type Dialer interface {
	Get(ctx context.Context, network string, str string, tag string) (netapi.Proxy, error)
}

func NewRoute(d Dialer, r Resolver, ProcessDumper netapi.ProcessDumper) *Route {
	rr := &Route{
		trie:       atomicx.NewPointer(newRouteTires()),
		customTrie: atomicx.NewPointer(newRouteTires()),
		config: &bypass.Config{
			Tcp: bypass.Mode_bypass,
			Udp: bypass.Mode_bypass,
		},
		r:             r,
		d:             d,
		ProcessDumper: ProcessDumper,
		RejectHistory: NewRejectHistory(),
	}

	rr.addMatchers()

	return rr
}

func (s *Route) Tags() iter.Seq[string] {
	tMaps := s.trie.Load().tagsMap
	cMaps := s.customTrie.Load().tagsMap

	return func(yield func(string) bool) {
		for v := range tMaps {
			if !yield(v) {
				return
			}
		}
		for v := range cMaps {
			if !yield(v) {
				return
			}
		}
	}
}

func (s *Route) Conn(ctx context.Context, host netapi.Address) (net.Conn, error) {
	result := s.dispatch(ctx, s.config.Tcp, host)

	if result.Mode.Mode() == bypass.Mode_block {
		s.RejectHistory.Push(ctx, "tcp", host.String())
	}

	p, err := s.d.Get(ctx, "tcp", result.Mode.Mode().String(), result.Mode.GetTag())
	if err != nil {
		return nil, netapi.NewDialError("tcp", err, host)
	}

	conn, err := p.Conn(ctx, host)
	if err != nil {
		return nil, netapi.NewDialError("tcp", err, host)
	}

	return conn, nil
}

func (s *Route) PacketConn(ctx context.Context, host netapi.Address) (net.PacketConn, error) {
	result := s.dispatch(ctx, s.config.Udp, host)

	if result.Mode.Mode() == bypass.Mode_block {
		s.RejectHistory.Push(ctx, "udp", host.String())
	}

	p, err := s.d.Get(ctx, "udp", result.Mode.Mode().String(), result.Mode.GetTag())
	if err != nil {
		return nil, netapi.NewDialError("udp", err, host)
	}

	conn, err := p.PacketConn(ctx, host)
	if err != nil {
		return nil, netapi.NewDialError("udp", err, host)
	}

	return conn, nil
}

func (s *Route) Dispatch(ctx context.Context, host netapi.Address) (netapi.Address, error) {
	store := netapi.GetContext(ctx)

	if store.SkipRoute {
		return host, nil
	}

	result := s.dispatch(ctx, bypass.Mode_bypass, host)
	return result.Addr, nil
}

func (s *Route) Search(ctx context.Context, addr netapi.Address) bypass.ModeEnum {
	mode, ok := s.customTrie.Load().trie.Search(ctx, addr)
	if ok {
		return mode.Value()
	}

	mode, ok = s.trie.Load().trie.Search(ctx, addr)
	if ok {
		return mode.Value()
	}

	return bypass.Proxy
}

func (s *Route) SearchProcess(ctx *netapi.Context, process netapi.Process) (bypass.ModeEnum, bool) {
	if process.Path == "" {
		return bypass.Bypass, false
	}

	matchProcess := filepath.Clean(strings.TrimSuffix(process.Path, " (deleted)"))

	matchProcess = convertVolumeName(matchProcess)

	if s.loopback.IsLoopback(ctx, matchProcess, process.Pid) {
		return bypass.Block, true
	}

	x, ok := s.customTrie.Load().processTrie.SearchString(matchProcess)
	if ok {
		return x.Value(), true
	}

	x, ok = s.trie.Load().processTrie.SearchString(matchProcess)
	if ok {
		return x.Value(), true
	}

	return bypass.Bypass, false
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

type routeResult struct {
	Mode   bypass.ModeEnum
	Addr   netapi.Address
	Reason string
}

type Object struct {
	Ctx         *netapi.Context
	NetowrkMode bypass.Mode
	Host        netapi.Address
}

type matcher struct {
	Name string
	Func func(*Object) bypass.ModeEnum
}

func (s *Route) AddMatcher(name string, f func(*Object) bypass.ModeEnum) {
	s.matchers = append(s.matchers, &matcher{Name: name, Func: f})
}

func (s *Route) addMatchers() {
	s.AddMatcher("loopback cycle check", func(o *Object) bypass.ModeEnum {
		if s.loopback.Cycle(o.Ctx, o.Host) {
			return bypass.Block
		}
		return bypass.Bypass
	})

	s.AddMatcher("force mode", func(o *Object) bypass.ModeEnum { return bypass.Mode(o.Ctx.ForceMode).ToModeEnum() })

	s.AddMatcher("network mode", func(o *Object) bypass.ModeEnum { return o.NetowrkMode.ToModeEnum() })

	s.AddMatcher("normal mode", func(o *Object) bypass.ModeEnum {
		var mode bypass.ModeEnum
		// get mode from bypass rule
		o.Ctx.Resolver.Resolver = s.r.Get("", "")
		if o.Ctx.Hosts == nil && !o.Host.IsFqdn() && o.Ctx.SniffHost() != "" {
			// reason = "sniff host trie mode"
			mode = s.Search(o.Ctx, netapi.ParseAddressPort(o.Host.Network(), o.Ctx.SniffHost(), o.Host.Port()))
		} else {
			// reason = "normal host trie mode"
			mode = s.Search(o.Ctx, o.Host)
		}

		switch mode.GetResolveStrategy() {
		case bypass.ResolveStrategy_only_ipv4, bypass.ResolveStrategy_prefer_ipv4:
			o.Ctx.Resolver.Mode = netapi.ResolverModePreferIPv4
		case bypass.ResolveStrategy_only_ipv6, bypass.ResolveStrategy_prefer_ipv6:
			o.Ctx.Resolver.Mode = netapi.ResolverModePreferIPv6
		default:
			if !configuration.IPv6.Load() {
				o.Ctx.Resolver.Mode = netapi.ResolverModePreferIPv4
			}
		}

		return mode
	})
}

func (s *Route) dispatch(ctx context.Context, networkMode bypass.Mode, host netapi.Address) routeResult {
	var mode bypass.ModeEnum
	var reason string

	process := s.dumpProcess(ctx, host.Network())

	// get mode from upstream specified
	store := netapi.GetContext(ctx)

	object := &Object{
		Ctx:         store,
		NetowrkMode: networkMode,
		Host:        host,
	}

	for _, m := range s.matchers {
		if mode = m.Func(object); !mode.Mode().Unspecified() {
			reason = m.Name
			break
		}
	}

	if mode.Mode() != bypass.Mode_block {
		if m, ok := s.SearchProcess(store, process); ok {
			mode, reason = m, "process trie mode"
		} else if !store.SniffMode.Unspecified() {
			mode, reason = store.SniffMode.ToModeEnum(), "sniff mode"
		}
	}

	store.Resolver.SkipResolve = s.skipResolve(mode)
	store.Mode = mode.Mode()
	store.Resolver.Resolver = s.r.Get(mode.Resolver(), s.getResolverFallback(mode))
	store.ModeReason = reason

	if s.config.ResolveLocally && host.IsFqdn() && mode.Mode() == bypass.Mode_proxy {
		// resolve proxy domain if resolveRemoteDomain enabled
		ip, err := dialer.ResolverIP(ctx, host)
		if err == nil {
			store.DomainString = host.String()
			host = netapi.ParseIPAddr(host.Network(), ip, host.Port())
			store.IPString = host.String()
		} else {
			log.Warn("resolve remote domain failed", "err", err)
		}
	}

	return routeResult{mode, host, reason}
}

func (s *Route) getResolverFallback(mode bypass.ModeEnum) string {
	switch mode.Mode() {
	case bypass.Mode_proxy:
		return s.config.ProxyResolver
	case bypass.Mode_direct:
		return s.config.DirectResolver
	}

	return ""
}

func (s *Route) Resolver(ctx context.Context, domain string) netapi.Resolver {
	host := netapi.ParseAddressPort("", domain, 0)
	netapi.GetContext(ctx).Resolver.Resolver = trie.SkipResolver
	mode := s.Search(ctx, host)
	if mode.Mode() == bypass.Mode_block {
		s.dumpProcess(ctx, "udp", "tcp")
		s.RejectHistory.Push(ctx, "dns", domain)
	}
	return s.r.Get(mode.Resolver(), s.getResolverFallback(mode))
}

func (f *Route) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) ([]net.IP, error) {
	return f.Resolver(ctx, domain).LookupIP(ctx, domain, opts...)
}

func (f *Route) Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	return f.Resolver(ctx, system.RelDomain(req.Name.String())).Raw(ctx, req)
}

func (f *Route) Close() error { return nil }

func (c *Route) dumpProcess(ctx context.Context, networks ...string) (s netapi.Process) {
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

		for _, network := range networks {
			process, err := c.ProcessDumper.ProcessName(network, sourceAddr, dst)
			if err != nil {
				// log.Warn("get process name failed", "err", err)
				continue
			}

			store.Process = process.Path
			store.ProcessPid = process.Pid
			store.ProcessUid = process.Uid
			return process
		}
	}

	return netapi.Process{}
}

func convertVolumeName(path string) string {
	vn := filepath.VolumeName(path)
	if vn == "" {
		if len(path) > 0 && path[0] == filepath.Separator {
			path = path[1:]
		}
		return path
	}

	return filepath.Join(vn, path[len(vn):])
}

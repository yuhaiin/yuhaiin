package route

import (
	"context"
	"iter"
	"net"
	"strings"
	"sync"

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

	customTrie *atomicx.Value[*routeTries]
	trie       *atomicx.Value[*routeTries]

	config *bypass.Config

	*RejectHistory

	mu sync.RWMutex
}

type Resolver interface {
	Get(str string) netapi.Resolver
}

type Dialer interface {
	Get(ctx context.Context, network string, str string, tag string) (netapi.Proxy, error)
}

func NewRoute(d Dialer, r Resolver, ProcessDumper netapi.ProcessDumper) *Route {
	return &Route{
		trie:       atomicx.NewValue(newRouteTires()),
		customTrie: atomicx.NewValue(newRouteTires()),
		config: &bypass.Config{
			Tcp: bypass.Mode_bypass,
			Udp: bypass.Mode_bypass,
		},
		r:             r,
		d:             d,
		ProcessDumper: ProcessDumper,
		RejectHistory: NewRejectHistory(),
	}
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
	mode, host, _ := s.dispatch(ctx, s.config.Tcp, host)

	if mode.Mode() == bypass.Mode_block {
		s.RejectHistory.Push(ctx, "tcp", host.String())
	}

	p, err := s.d.Get(ctx, "tcp", mode.Mode().String(), mode.GetTag())
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
	mode, host, _ := s.dispatch(ctx, s.config.Udp, host)

	if mode.Mode() == bypass.Mode_block {
		s.RejectHistory.Push(ctx, "udp", host.String())
	}

	p, err := s.d.Get(ctx, "udp", mode.Mode().String(), mode.GetTag())
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

	_, addr, _ := s.dispatch(ctx, bypass.Mode_bypass, host)
	return addr, nil
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

func (s *Route) SearchProcess(ctx context.Context, process string) (bypass.ModeEnum, bool) {
	matchProcess := strings.TrimSuffix(process, " (deleted)")
	x, ok := s.customTrie.Load().processTrie[matchProcess]
	if ok {
		return x.Value(), true
	}

	x, ok = s.trie.Load().processTrie[matchProcess]
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

func (s *Route) dispatch(ctx context.Context, networkMode bypass.Mode, host netapi.Address) (mode bypass.ModeEnum, addr netapi.Address, reason string) {
	process := s.dumpProcess(ctx, host.Network())

	// get mode from upstream specified
	store := netapi.GetContext(ctx)

	if mode.Mode() == bypass.Mode_bypass {
		if bypass.Mode(store.ForceMode) != bypass.Mode_bypass {
			reason = "context force mode"
			mode = bypass.Mode(store.ForceMode).ToModeEnum()
		} else {
			reason = "network mode"
			mode = networkMode.ToModeEnum() // get mode from network(tcp/udp) rule
		}
	}

	if mode.Mode() == bypass.Mode_bypass {
		// get mode from bypass rule
		store.Resolver.Resolver = s.r.Get("")
		if !host.IsFqdn() && store.SniffHost() != "" {
			reason = "sniff host trie mode"
			mode = s.Search(ctx, netapi.ParseAddressPort(host.Network(), store.SniffHost(), host.Port()))
		} else {
			reason = "normal host trie mode"
			mode = s.Search(ctx, host)
		}

		switch mode.GetResolveStrategy() {
		case bypass.ResolveStrategy_only_ipv4, bypass.ResolveStrategy_prefer_ipv4:
			store.Resolver.Mode = netapi.ResolverModePreferIPv4
		case bypass.ResolveStrategy_only_ipv6, bypass.ResolveStrategy_prefer_ipv6:
			store.Resolver.Mode = netapi.ResolverModePreferIPv6
		default:
			if !configuration.IPv6.Load() {
				store.Resolver.Mode = netapi.ResolverModePreferIPv4
			}
		}
	}

	if mode.Mode() != bypass.Mode_block {
		if store.SniffMode != bypass.Mode_bypass {
			mode = store.SniffMode.ToModeEnum()
		} else if process != "" {
			if m, ok := s.SearchProcess(ctx, process); ok {
				reason = "process trie mode"
				mode = m
			}
		}
	}

	store.Resolver.SkipResolve = s.skipResolve(mode)
	store.Mode = mode.Mode()
	store.Resolver.Resolver = s.r.Get(mode.Mode().String())
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

	return mode, host, reason
}

func (s *Route) Resolver(ctx context.Context, domain string) netapi.Resolver {
	host := netapi.ParseAddressPort("", domain, 0)
	netapi.GetContext(ctx).Resolver.Resolver = trie.SkipResolver
	mode := s.Search(ctx, host)
	if mode.Mode() == bypass.Mode_block {
		s.dumpProcess(ctx, "udp", "tcp")
		s.RejectHistory.Push(ctx, "dns", domain)
	}
	return s.r.Get(mode.Mode().String())
}

func (f *Route) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) ([]net.IP, error) {
	return f.Resolver(ctx, domain).LookupIP(ctx, domain, opts...)
}

func (f *Route) Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	return f.Resolver(ctx, system.RelDomain(req.Name.String())).Raw(ctx, req)
}

func (f *Route) Close() error { return nil }

func (c *Route) dumpProcess(ctx context.Context, networks ...string) (s string) {
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

			store.Process = process
			return process
		}
	}

	return ""
}

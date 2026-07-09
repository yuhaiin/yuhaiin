package route

import (
	"context"
	"iter"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"github.com/miekg/dns"
)

type Route struct {
	ProcessDumper netapi.ProcessDumper

	r Resolver
	d Dialer

	config *atomicx.Value[*RouteConfig]
	ms     *Matchers

	*RejectHistory

	matchers []*matcher

	loopback LoopbackDetector
}

type Resolver interface {
	Get(resolver, fallback string) netapi.Resolver
}

type Dialer interface {
	Get(ctx context.Context, network string, str string, tag string) (netapi.Proxy, error)
}

func NewRoute(d Dialer, r Resolver, list *Lists, ProcessDumper netapi.ProcessDumper) *Route {
	rr := &Route{
		config:        atomicx.NewValue(&RouteConfig{}),
		r:             r,
		d:             d,
		ProcessDumper: ProcessDumper,
		RejectHistory: NewRejectHistory(),
		ms:            NewMatchers(list),
	}

	rr.addMatchers()

	return rr
}

func (s *Route) Tags() iter.Seq[string] { return s.ms.Tags() }

func (s *Route) Conn(ctx context.Context, host netapi.Address) (net.Conn, error) {
	result := s.dispatch(ctx, host)

	if result.Mode.Mode() == ModeBlock {
		s.Push(ctx, "tcp", host.String())
	}

	p, err := s.d.Get(ctx, "tcp", result.Mode.Mode().String(), result.Mode.GetTag())
	if err != nil {
		return nil, netapi.NewDialError("tcp", err, result.Addr)
	}

	conn, err := p.Conn(ctx, result.Addr)
	if err != nil {
		return nil, netapi.NewDialError("tcp", err, result.Addr)
	}

	return conn, nil
}

func (s *Route) PacketConn(ctx context.Context, host netapi.Address) (net.PacketConn, error) {
	result := s.dispatch(ctx, host)

	if result.Mode.Mode() == ModeBlock {
		s.Push(ctx, "udp", host.String())
	}

	p, err := s.d.Get(ctx, "udp", result.Mode.Mode().String(), result.Mode.GetTag())
	if err != nil {
		return nil, netapi.NewDialError("udp", err, result.Addr)
	}

	conn, err := p.PacketConn(ctx, result.Addr)
	if err != nil {
		return nil, netapi.NewDialError("udp", err, result.Addr)
	}

	return conn, nil
}

func (s *Route) Ping(ctx context.Context, host netapi.Address) (uint64, error) {
	result := s.dispatch(ctx, host)

	if result.Mode.Mode() == ModeBlock {
		s.Push(ctx, "ping", host.String())
	}

	p, err := s.d.Get(ctx, "udp", result.Mode.Mode().String(), result.Mode.GetTag())
	if err != nil {
		return 0, netapi.NewDialError("udp", err, result.Addr)
	}

	return p.Ping(ctx, result.Addr)
}

func (s *Route) Dispatch(ctx context.Context, host netapi.Address) (netapi.Address, error) {
	if netapi.GetContext(ctx).ConnOptions().SkipRoute() {
		return host, nil
	}
	return s.dispatch(ctx, host).Addr, nil
}

func (s *Route) skipResolve(mode ModeEnum) bool {
	if mode.Mode() != ModeProxy {
		return false
	}

	switch s.config.Load().UDPProxyFQDNStrategy {
	case UDPProxyFQDNSkipResolve:
		return mode.UdpProxyFqdn() != UDPProxyFQDNResolve
	default:
		return mode.UdpProxyFqdn() == UDPProxyFQDNSkipResolve
	}
}

func routeModeFromString(mode string) Mode {
	return parseMode(mode)
}

type routeResult struct {
	Addr netapi.Address
	Mode ModeEnum
}

type matcher struct {
	Match func(context.Context, netapi.Address) ModeEnum
	Name  string
}

func (s *Route) AddMatcher(name string, f func(context.Context, netapi.Address) ModeEnum) {
	s.matchers = append(s.matchers, &matcher{Name: name, Match: f})
}

func (s *Route) addMatchers() {
	s.AddMatcher("loopback cycle check", func(ctx context.Context, host netapi.Address) ModeEnum {
		store := netapi.GetContext(ctx)

		if s.loopback.Cycle(store, host) {
			return Block
		}

		processPath, pid, _ := store.GetProcess()

		if processPath != "" || pid != 0 {
			// make all go system dial direct, eg: tailscale
			if processPath == "io.github.asutorufa.yuhaiin" {
				return Direct
			}

			matchProcess := filepath.Clean(strings.TrimSuffix(processPath, " (deleted)"))

			matchProcess = convertVolumeName(matchProcess)

			if s.loopback.IsLoopback(store, matchProcess, pid) {
				return Block
			}
		}

		return Bypass
	})

	s.AddMatcher("context route mode", func(ctx context.Context, host netapi.Address) ModeEnum {
		return ModeEnum{mode: routeModeFromString(netapi.GetContext(ctx).ConnOptions().RouteMode()), resolveStrategy: ResolveDefault, udpProxyFQDNStrategy: UDPProxyFQDNDefault}
	})

	s.AddMatcher("normal mode", func(ctx context.Context, host netapi.Address) ModeEnum {
		store := netapi.GetContext(ctx)

		if store.GetHosts() == nil && !host.IsFqdn() && store.SniffHost() != "" {
			addr, err := netapi.ParseAddressPort(host.Network(), store.SniffHost(), host.Port())
			if err == nil {
				host = addr
			} else {
				log.Warn("parse sniff host failed", "err", err, "host", store.SniffHost())
			}
		}

		mode := s.ms.Match(ctx, host)

		switch mode.GetResolveStrategy() {
		case ResolveOnlyIPv4, ResolvePreferIPv4:
			store.ConnOptions().Resolver().SetMode(netapi.ResolverModePreferIPv4)
		case ResolveOnlyIPv6, ResolvePreferIPv6:
			store.ConnOptions().Resolver().SetMode(netapi.ResolverModePreferIPv6)
		default:
			if !configuration.IPv6.Load() {
				store.ConnOptions().Resolver().SetMode(netapi.ResolverModePreferIPv4)
			}
		}

		return mode
	})
}

func (s *Route) dispatch(ctx context.Context, addr netapi.Address) routeResult {
	s.dumpProcess(ctx, addr.Network())

	store := netapi.GetContext(ctx)

	store.ConnOptions().Resolver().SetResolver(s.r.Get(s.getResolverFallback(ProxyMode), ""))

	if geo := s.ms.list.LoadGeoip(); geo != nil {
		if country, err := geo.LookupAddr(ctx, addr); err == nil {
			store.SetGeo(country)
			metrics.Counter.AddGeoCountry(country)
		}

		store.ConnOptions().SetMaxminddb(geo)
	}

	start := system.CheapNowNano()

	store.ConnOptions().
		AddLists(s.ms.list.HostTrie().Search(ctx, addr)...).
		AddLists(s.ms.list.ProcessTrie().Search(ctx, addr)...)

	var mode ModeEnum
	for _, m := range s.matchers {
		if mode = m.Match(ctx, addr); !mode.Mode().Unspecified() {
			break
		}
	}

	metrics.Counter.AddTrieMatchDuration(float64(time.Duration(system.CheapNowNano() - start).Milliseconds()))

	store.ConnOptions().Resolver().SetUdpSkipResolveTarget(s.skipResolve(mode))
	store.ConnOptions().Resolver().SetResolver(s.r.Get(mode.Resolver(), s.getResolverFallback(mode)))
	store.ConnOptions().SetRouteMode(mode.Mode().String())

	if s.config.Load().ResolveLocally && addr.IsFqdn() && mode.Mode() == ModeProxy {
		// resolve proxy domain if resolveRemoteDomain enabled
		ip, err := netapi.ResolverIP(ctx, addr.Hostname())
		if err == nil {
			store.SetDomainString(addr.String())
			addr = netapi.ParseIPAddr(addr.Network(), ip.Rand(), addr.Port())
			store.SetIPString(addr.String())
		} else {
			log.Warn("resolve remote domain failed", "err", err)
		}
	}

	return routeResult{addr, mode}
}

func (s *Route) getResolverFallback(mode ModeEnum) string {
	switch mode.Mode() {
	case ModeProxy:
		return s.config.Load().ProxyResolver
	case ModeDirect:
		return s.config.Load().DirectResolver
	case ModeBlock:
		return ModeBlock.String()
	}

	return ""
}

func (s *Route) Resolver(ctx context.Context, domain string) netapi.Resolver {
	host, err := netapi.ParseAddressPort("", domain, 0)
	if err != nil {
		return netapi.ErrorResolver(func(domain string) error { return err })
	}

	netapi.GetContext(ctx).ConnOptions().
		AddLists(s.ms.list.HostTrie().Search(ctx, host)...).
		AddLists(s.ms.list.ProcessTrie().Search(ctx, host)...)

	mode := s.ms.Match(ctx, host)

	if mode.Mode() == ModeBlock {
		s.dumpProcess(ctx, "udp", "tcp")
		s.Push(ctx, "dns", domain)
	}

	return s.r.Get(mode.Resolver(), s.getResolverFallback(mode))
}

func (f *Route) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	return f.Resolver(ctx, domain).LookupIP(ctx, domain, opts...)
}

func (f *Route) Raw(ctx context.Context, req dns.Question) (dns.Msg, error) {
	return f.Resolver(ctx, system.RelDomain(req.Name)).Raw(ctx, req)
}

func (f *Route) Close() error { return nil }

func (f *Route) Name() string { return "route" }

func (c *Route) dumpProcess(ctx context.Context, networks ...string) (s netapi.Process) {
	if c.ProcessDumper == nil || !c.shouldDumpProcess() {
		return
	}

	store := netapi.GetContext(ctx)

	var dst []net.Addr
	if store.GetInbound() != nil {
		dst = append(dst, store.GetInbound())
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

			store.SetProcess(process.Path, process.Pid, process.Uid)
			return process
		}
	}

	return netapi.Process{}
}

func (c *Route) shouldDumpProcess() bool {
	switch configuration.ProcessLookupMode.Load() {
	case "off":
		return false
	case "rules_only":
		return !c.ms.list.ProcessTrie().Empty()
	default:
		return true
	}
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

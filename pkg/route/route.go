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
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"github.com/miekg/dns"
)

type Route struct {
	ProcessDumper netapi.ProcessDumper

	r Resolver
	d Dialer

	config *atomicx.Value[*config.Configv2]
	ms     *Matchers

	loopback LoopbackDetector

	*RejectHistory

	matchers []*matcher
}

type Resolver interface {
	Get(resolver, fallback string) netapi.Resolver
}

type Dialer interface {
	Get(ctx context.Context, network string, str string, tag string) (netapi.Proxy, error)
}

func NewRoute(d Dialer, r Resolver, list *Lists, ProcessDumper netapi.ProcessDumper) *Route {
	rr := &Route{
		config:        atomicx.NewValue(&config.Configv2{}),
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
	if store := netapi.GetContext(ctx); store.ConnOptions().SystemDialer() {
		return dialer.DialHappyEyeballsv2(ctx, host)
	}

	result := s.dispatch(ctx, host)

	if result.Mode.Mode() == config.Mode_block {
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
	if netapi.GetContext(ctx).ConnOptions().SystemDialer() {
		return dialer.ListenPacket(ctx, "udp", "0.0.0.0:0")
	}

	result := s.dispatch(ctx, host)

	if result.Mode.Mode() == config.Mode_block {
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
	if netapi.GetContext(ctx).ConnOptions().SystemDialer() {
		return direct.Default.Ping(ctx, host)
	}

	result := s.dispatch(ctx, host)

	if result.Mode.Mode() == config.Mode_block {
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

func (s *Route) skipResolve(mode config.ModeEnum) bool {
	if mode.Mode() != config.Mode_proxy {
		return false
	}

	switch s.config.Load().GetUdpProxyFqdn() {
	case config.UdpProxyFqdnStrategy_skip_resolve:
		return mode.UdpProxyFqdn() != config.UdpProxyFqdnStrategy_resolve
	default:
		return mode.UdpProxyFqdn() == config.UdpProxyFqdnStrategy_skip_resolve
	}
}

type routeResult struct {
	Addr netapi.Address
	Mode config.ModeEnum
}

type matcher struct {
	Match func(context.Context, netapi.Address) config.ModeEnum
	Name  string
}

func (s *Route) AddMatcher(name string, f func(context.Context, netapi.Address) config.ModeEnum) {
	s.matchers = append(s.matchers, &matcher{Name: name, Match: f})
}

func (s *Route) addMatchers() {
	s.AddMatcher("loopback cycle check", func(ctx context.Context, host netapi.Address) config.ModeEnum {
		store := netapi.GetContext(ctx)

		if s.loopback.Cycle(store, host) {
			return config.Block
		}

		processPath, pid, _ := store.GetProcess()

		if processPath != "" || pid != 0 {
			// make all go system dial direct, eg: tailscale
			if processPath == "io.github.asutorufa.yuhaiin" {
				return config.Direct
			}

			matchProcess := filepath.Clean(strings.TrimSuffix(processPath, " (deleted)"))

			matchProcess = convertVolumeName(matchProcess)

			if s.loopback.IsLoopback(store, matchProcess, pid) {
				return config.Block
			}
		}

		return config.Bypass
	})

	s.AddMatcher("context route mode", func(ctx context.Context, host netapi.Address) config.ModeEnum {
		return config.Mode(netapi.GetContext(ctx).ConnOptions().RouteMode()).ToModeEnum()
	})

	s.AddMatcher("normal mode", func(ctx context.Context, host netapi.Address) config.ModeEnum {
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
		case config.ResolveStrategy_only_ipv4, config.ResolveStrategy_prefer_ipv4:
			store.ConnOptions().Resolver().SetMode(netapi.ResolverModePreferIPv4)
		case config.ResolveStrategy_only_ipv6, config.ResolveStrategy_prefer_ipv6:
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

	store.ConnOptions().Resolver().SetResolver(s.r.Get(s.getResolverFallback(config.ProxyMode), ""))

	if geo := s.ms.list.LoadGeoip(); geo != nil {
		if country, err := geo.LookupAddr(ctx, addr); err == nil {
			store.SetGeo(country)
		}

		store.ConnOptions().SetMaxminddb(geo)
	}

	store.ConnOptions().
		AddLists(s.ms.list.HostTrie().Search(ctx, addr)...).
		AddLists(s.ms.list.ProcessTrie().Search(ctx, addr)...)

	start := system.CheapNowNano()
	var mode config.ModeEnum
	for _, m := range s.matchers {
		if mode = m.Match(ctx, addr); !mode.Mode().Unspecified() {
			break
		}
	}

	metrics.Counter.AddTrieMatchDuration(float64(time.Duration(system.CheapNowNano() - start).Milliseconds()))

	store.ConnOptions().Resolver().SetUdpSkipResolveTarget(s.skipResolve(mode))
	store.ConnOptions().Resolver().SetResolver(s.r.Get(mode.Resolver(), s.getResolverFallback(mode)))

	store.Mode = mode.Mode()

	if s.config.Load().GetResolveLocally() && addr.IsFqdn() && mode.Mode() == config.Mode_proxy {
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

func (s *Route) getResolverFallback(mode config.ModeEnum) string {
	switch mode.Mode() {
	case config.Mode_proxy:
		return s.config.Load().GetProxyResolver()
	case config.Mode_direct:
		return s.config.Load().GetDirectResolver()
	case config.Mode_block:
		return config.Mode_block.String()
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

	if mode.Mode() == config.Mode_block {
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
	if c.ProcessDumper == nil {
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

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
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"github.com/miekg/dns"
)

type Route struct {
	ProcessDumper netapi.ProcessDumper

	r Resolver
	d Dialer

	config *atomicx.Value[*bypass.Configv2]
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
		config:        atomicx.NewValue(&bypass.Configv2{}),
		r:             r,
		d:             d,
		ProcessDumper: ProcessDumper,
		RejectHistory: NewRejectHistory(),
		ms:            NewMatchers(list),
	}

	rr.addMatchers()

	return rr
}

func (s *Route) Tags() iter.Seq[string] {
	return func(yield func(string) bool) {
		for v := range s.ms.Tags() {
			if !yield(v) {
				return
			}
		}
	}
}

func (s *Route) Conn(ctx context.Context, host netapi.Address) (net.Conn, error) {
	store := netapi.GetContext(ctx)

	var addr string
	if store.SystemDialer {
		if host.IsFqdn() {
			store.SetDomainString(host.String())
			taddr, err := dialer.ResolveTCPAddr(ctx, host)
			if err != nil {
				return nil, netapi.NewDialError("tcp", err, host)
			}
			addr = taddr.String()
		} else {
			addr = host.String()
		}

		return dialer.DialContext(ctx, "tcp", addr)
	}

	result := s.dispatch(store, host)

	if result.Mode.Mode() == bypass.Mode_block {
		s.Push(ctx, "tcp", host.String())
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
	store := netapi.GetContext(ctx)

	if store.SystemDialer {
		return dialer.ListenPacket(ctx, "udp", "0.0.0.0:0")
	}

	result := s.dispatch(store, host)

	if result.Mode.Mode() == bypass.Mode_block {
		s.Push(ctx, "udp", host.String())
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

func (s *Route) Ping(ctx context.Context, host netapi.Address) (uint64, error) {
	store := netapi.GetContext(ctx)

	if store.SystemDialer {
		return direct.Default.Ping(ctx, host)
	}

	result := s.dispatch(store, host)

	if result.Mode.Mode() == bypass.Mode_block {
		s.Push(ctx, "ping", host.String())
	}

	p, err := s.d.Get(ctx, "udp", result.Mode.Mode().String(), result.Mode.GetTag())
	if err != nil {
		return 0, netapi.NewDialError("udp", err, host)
	}

	return p.Ping(ctx, host)
}

func (s *Route) Dispatch(ctx context.Context, host netapi.Address) (netapi.Address, error) {
	if ctx.Value(netapi.SkipRouteKey{}) == true {
		return host, nil
	}

	// get mode from upstream specified
	store := netapi.GetContext(ctx)

	result := s.dispatch(store, host)
	return result.Addr, nil
}

func (s *Route) skipResolve(mode bypass.ModeEnum) bool {
	if mode.Mode() != bypass.Mode_proxy {
		return false
	}

	switch s.config.Load().GetUdpProxyFqdn() {
	case bypass.UdpProxyFqdnStrategy_skip_resolve:
		return mode.UdpProxyFqdn() != bypass.UdpProxyFqdnStrategy_resolve
	default:
		return mode.UdpProxyFqdn() == bypass.UdpProxyFqdnStrategy_skip_resolve
	}
}

type routeResult struct {
	Addr netapi.Address
	Mode bypass.ModeEnum
}

type Object struct {
	Host netapi.Address
	Ctx  *netapi.Context
}

type matcher struct {
	Func func(*Object) bypass.ModeEnum
	Name string
}

func (s *Route) AddMatcher(name string, f func(*Object) bypass.ModeEnum) {
	s.matchers = append(s.matchers, &matcher{Name: name, Func: f})
}

func (s *Route) addMatchers() {
	s.AddMatcher("loopback cycle check", func(o *Object) bypass.ModeEnum {
		if s.loopback.Cycle(o.Ctx, o.Host) {
			return bypass.Block
		}

		processPath, pid, _ := o.Ctx.GetProcess()

		if processPath != "" || pid != 0 {
			// make all go system dial direct, eg: tailscale
			if processPath == "io.github.asutorufa.yuhaiin" {
				return bypass.Direct
			}

			matchProcess := filepath.Clean(strings.TrimSuffix(processPath, " (deleted)"))

			matchProcess = convertVolumeName(matchProcess)

			if s.loopback.IsLoopback(o.Ctx, matchProcess, pid) {
				return bypass.Block
			}
		}

		return bypass.Bypass
	})

	s.AddMatcher("force mode", func(o *Object) bypass.ModeEnum {
		return bypass.Mode(o.Ctx.ForceMode).ToModeEnum()
	})

	s.AddMatcher("normal mode", func(o *Object) bypass.ModeEnum {
		o.Ctx.Resolver.Resolver = s.r.Get(s.getResolverFallback(bypass.Proxy), "")

		host := o.Host
		if o.Ctx.GetHosts() == nil && !o.Host.IsFqdn() && o.Ctx.SniffHost() != "" {
			addr, err := netapi.ParseAddressPort(o.Host.Network(), o.Ctx.SniffHost(), o.Host.Port())
			if err == nil {
				host = addr
			} else {
				log.Warn("parse sniff host failed", "err", err, "host", o.Ctx.SniffHost())
			}
		}

		mode := s.ms.Match(o.Ctx, host)

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

func (s *Route) dispatch(store *netapi.Context, host netapi.Address) routeResult {

	s.dumpProcess(store, host.Network())

	object := &Object{
		Ctx:  store,
		Host: host,
	}

	start := system.CheapNowNano()
	var mode bypass.ModeEnum
	for _, m := range s.matchers {
		if mode = m.Func(object); !mode.Mode().Unspecified() {
			break
		}
	}
	metrics.Counter.AddTrieMatchDuration(float64(time.Duration(system.CheapNowNano() - start).Milliseconds()))

	store.Resolver.SkipResolve = s.skipResolve(mode)
	store.Mode = mode.Mode()
	store.Resolver.Resolver = s.r.Get(mode.Resolver(), s.getResolverFallback(mode))

	if s.config.Load().GetResolveLocally() && host.IsFqdn() && mode.Mode() == bypass.Mode_proxy {
		// resolve proxy domain if resolveRemoteDomain enabled
		ip, err := dialer.ResolverIP(store, host)
		if err == nil {
			store.SetDomainString(host.String())
			host = netapi.ParseIPAddr(host.Network(), ip, host.Port())
			store.SetIPString(host.String())
		} else {
			log.Warn("resolve remote domain failed", "err", err)
		}
	}

	return routeResult{host, mode}
}

func (s *Route) getResolverFallback(mode bypass.ModeEnum) string {
	switch mode.Mode() {
	case bypass.Mode_proxy:
		return s.config.Load().GetProxyResolver()
	case bypass.Mode_direct:
		return s.config.Load().GetDirectResolver()
	case bypass.Mode_block:
		return bypass.Mode_block.String()
	}

	return ""
}

func (s *Route) Resolver(ctx context.Context, domain string) netapi.Resolver {
	host, err := netapi.ParseAddressPort("", domain, 0)
	if err != nil {
		return netapi.ErrorResolver(func(domain string) error { return err })
	}

	mode := s.ms.Match(setResolverMatch(ctx), host)

	if mode.Mode() == bypass.Mode_block {
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

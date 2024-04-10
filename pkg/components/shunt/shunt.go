package shunt

import (
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/utils/convert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"golang.org/x/exp/maps"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/protobuf/proto"
)

type modeMarkKey struct{}

func (modeMarkKey) String() string { return "MODE" }

type DOMAIN_MARK_KEY struct{}

type IP_MARK_KEY struct{}

func (IP_MARK_KEY) String() string { return "IP" }

type ForceModeKey struct{}

type Shunt struct {
	resolveDomain bool
	modifiedTime  int64

	config       *bypass.BypassConfig
	mapper       *trie.Trie[bypass.ModeEnum]
	customMapper *trie.Trie[bypass.ModeEnum]

	processMapper syncmap.SyncMap[string, bypass.ModeEnum]
	ProcessDumper netapi.ProcessDumper

	mu sync.RWMutex

	r Resolver
	d Dialer

	tags map[string]struct{}
}

type Resolver interface {
	Get(str string) netapi.Resolver
}
type Dialer interface {
	Get(ctx context.Context, network string, str string, tag string) (netapi.Proxy, error)
}

func NewShunt(d Dialer, r Resolver, ProcessDumper netapi.ProcessDumper) *Shunt {
	return &Shunt{
		mapper:       trie.NewTrie[bypass.ModeEnum](),
		customMapper: trie.NewTrie[bypass.ModeEnum](),
		config: &bypass.BypassConfig{
			Tcp: bypass.Mode_bypass,
			Udp: bypass.Mode_bypass,
		},
		r:             r,
		d:             d,
		ProcessDumper: ProcessDumper,
		tags:          make(map[string]struct{}),
	}
}

func (s *Shunt) Update(c *pc.Setting) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.resolveDomain = c.Dns.ResolveRemoteDomain

	if !slices.EqualFunc(
		s.config.CustomRuleV3,
		c.Bypass.CustomRuleV3,
		func(mc1, mc2 *bypass.ModeConfig) bool { return proto.Equal(mc1, mc2) },
	) {
		s.customMapper.Clear() //nolint:errcheck
		s.processMapper = syncmap.SyncMap[string, bypass.ModeEnum]{}

		for _, v := range c.Bypass.CustomRuleV3 {
			mark := v.ToModeEnum()

			if mark.GetTag() != "" {
				s.tags[mark.GetTag()] = struct{}{}
			}

			for _, hostname := range v.Hostname {
				if strings.HasPrefix(hostname, "process:") {
					s.processMapper.Store(hostname[8:], mark)
				} else {
					s.customMapper.Insert(hostname, mark)
				}
			}
		}
	}

	modifiedTime := s.modifiedTime
	if stat, err := os.Stat(c.Bypass.BypassFile); err == nil {
		modifiedTime = stat.ModTime().Unix()
	}

	if s.config.BypassFile != c.Bypass.BypassFile || s.modifiedTime != modifiedTime {
		s.mapper.Clear() //nolint:errcheck
		s.tags = make(map[string]struct{})
		s.modifiedTime = modifiedTime
		rangeRule(c.Bypass.BypassFile, func(s1 string, s2 bypass.ModeEnum) {
			if strings.HasPrefix(s1, "process:") {
				s.processMapper.Store(s1[8:], s2.Mode())
			} else {
				s.mapper.Insert(s1, s2)
			}

			if s2.GetTag() != "" {
				s.tags[s2.GetTag()] = struct{}{}
			}
		})
	}

	s.config = c.Bypass
}

func (s *Shunt) Tags() []string { return maps.Keys(s.tags) }

func (s *Shunt) Conn(ctx context.Context, host netapi.Address) (net.Conn, error) {
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

func (s *Shunt) PacketConn(ctx context.Context, host netapi.Address) (net.PacketConn, error) {
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

func (s *Shunt) Dispatch(ctx context.Context, host netapi.Address) (netapi.Address, error) {
	_, addr := s.dispatch(ctx, bypass.Mode_bypass, host)
	return addr, nil
}

func (s *Shunt) Search(ctx context.Context, addr netapi.Address) bypass.ModeEnum {
	mode, ok := s.customMapper.Search(ctx, addr)
	if ok {
		return mode
	}

	mode, ok = s.mapper.Search(ctx, addr)
	if ok {
		return mode
	}

	return bypass.Mode_proxy
}

func (s *Shunt) dispatch(ctx context.Context, networkMode bypass.Mode, host netapi.Address) (bypass.ModeEnum, netapi.Address) {
	var mode bypass.ModeEnum = bypass.Mode_bypass

	process := s.DumpProcess(ctx, host)
	if process != "" {
		m, ok := s.processMapper.Load(process)
		if ok {
			mode = m
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

func (s *Shunt) Resolver(ctx context.Context, domain string) netapi.Resolver {
	host := netapi.ParseAddressPort(0, domain, netapi.EmptyPort)
	host.SetResolver(trie.SkipResolver)
	return s.r.Get(s.Search(ctx, host).Mode().String())
}

func (f *Shunt) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) ([]net.IP, error) {
	return f.Resolver(ctx, domain).LookupIP(ctx, domain, opts...)
}

func (f *Shunt) Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	return f.Resolver(ctx, strings.TrimSuffix(req.Name.String(), ".")).Raw(ctx, req)
}

func (f *Shunt) Close() error { return nil }

func (c *Shunt) DumpProcess(ctx context.Context, addr netapi.Address) (s string) {
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
			log.Warn("get process name failed", "err", err)
			continue
		}

		store.Add("Process", process)
		return process
	}

	return ""
}

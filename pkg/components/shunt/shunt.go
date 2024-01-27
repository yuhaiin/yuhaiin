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
	"github.com/Asutorufa/yuhaiin/pkg/net/mapper"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
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
	mapper       *mapper.Combine[bypass.ModeEnum]
	customMapper *mapper.Combine[bypass.ModeEnum]
	mu           sync.RWMutex

	Opts

	tags map[string]struct{}
}

type Opts struct {
	DirectDialer   netapi.Proxy
	DirectResolver netapi.Resolver
	ProxyDialer    netapi.Proxy
	ProxyResolver  netapi.Resolver
	BlockDialer    netapi.Proxy
	BLockResolver  netapi.Resolver
	DefaultMode    bypass.Mode
}

func NewShunt(opt Opts) *Shunt {
	if opt.DefaultMode != bypass.Mode_block && opt.DefaultMode != bypass.Mode_direct && opt.DefaultMode != bypass.Mode_proxy {
		opt.DefaultMode = bypass.Mode_proxy
	}

	return &Shunt{
		mapper:       mapper.NewMapper[bypass.ModeEnum](),
		customMapper: mapper.NewMapper[bypass.ModeEnum](),
		config: &bypass.BypassConfig{
			Tcp: bypass.Mode_bypass,
			Udp: bypass.Mode_bypass,
		},
		Opts: opt,
		tags: make(map[string]struct{}),
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

		for _, v := range c.Bypass.CustomRuleV3 {
			mark := v.ToModeEnum()

			if mark.GetTag() != "" {
				s.tags[mark.GetTag()] = struct{}{}
			}

			for _, hostname := range v.Hostname {
				s.customMapper.Insert(hostname, mark)
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
			s.mapper.Insert(s1, s2)
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

	conn, err := s.dialer(mode).Conn(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	return conn, nil
}

func (s *Shunt) PacketConn(ctx context.Context, host netapi.Address) (net.PacketConn, error) {
	mode, host := s.dispatch(ctx, s.config.Udp, host)

	conn, err := s.dialer(mode).PacketConn(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	return conn, nil
}

func (s *Shunt) Dispatch(ctx context.Context, host netapi.Address) (netapi.Address, error) {
	_, addr := s.dispatch(ctx, bypass.Mode_bypass, host)
	return addr, nil
}

func (s *Shunt) SearchWithDefault(ctx context.Context, addr netapi.Address, defaultT bypass.ModeEnum) bypass.ModeEnum {
	mode, ok := s.customMapper.Search(ctx, addr)
	if ok {
		return mode
	}

	mode, ok = s.mapper.Search(ctx, addr)
	if ok {
		return mode
	}

	return defaultT
}

func (s *Shunt) dispatch(ctx context.Context, networkMode bypass.Mode, host netapi.Address) (bypass.Mode, netapi.Address) {
	// get mode from upstream specified

	store := netapi.StoreFromContext(ctx)

	mode := netapi.GetDefault[bypass.Mode](
		ctx,
		ForceModeKey{},
		networkMode, // get mode from network(tcp/udp) rule
	)

	if mode == bypass.Mode_bypass {
		// get mode from bypass rule
		host.SetResolver(s.resolver(s.DefaultMode))
		fields := s.SearchWithDefault(ctx, host, s.DefaultMode)
		mode = fields.Mode()

		// get tag from bypass rule
		if tag := fields.GetTag(); len(tag) != 0 {
			store.Add(node.TagKey{}, tag)
		}

		if fields.GetResolveStrategy() == bypass.ResolveStrategy_prefer_ipv6 {
			host.PreferIPv6(true)
		}
	}

	store.Add(modeMarkKey{}, mode)
	host.SetResolver(s.resolver(mode))

	if s.resolveDomain && host.Type() == netapi.DOMAIN && mode == bypass.Mode_proxy {
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

func (s *Shunt) dialer(m bypass.Mode) netapi.Proxy {
	switch m {
	case bypass.Mode_block:
		return s.BlockDialer
	case bypass.Mode_direct:
		return s.DirectDialer
	case bypass.Mode_proxy:
		return s.ProxyDialer
	default:
		return s.dialer(s.DefaultMode)
	}
}

func (s *Shunt) resolver(m bypass.Mode) netapi.Resolver {
	switch m {
	case bypass.Mode_block:
		return s.BLockResolver
	case bypass.Mode_direct:
		return s.DirectResolver
	case bypass.Mode_proxy:
		return s.ProxyResolver
	default:
		return s.resolver(s.DefaultMode)
	}
}

func (s *Shunt) Resolver(ctx context.Context, domain string) netapi.Resolver {
	host := netapi.ParseAddressPort(0, domain, netapi.EmptyPort)
	host.SetResolver(mapper.SkipResolver)
	return s.resolver(s.SearchWithDefault(ctx, host, s.DefaultMode).Mode())
}

func (f *Shunt) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) ([]net.IP, error) {
	return f.Resolver(ctx, domain).LookupIP(ctx, domain, opts...)
}

func (f *Shunt) Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	return f.Resolver(ctx, strings.TrimSuffix(req.Name.String(), ".")).Raw(ctx, req)
}

func (f *Shunt) Close() error { return nil }

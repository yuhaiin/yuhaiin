package shunt

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/mapper"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"golang.org/x/net/dns/dnsmessage"
)

type modeMarkKey struct{}

func (modeMarkKey) String() string { return "MODE" }

type DOMAIN_MARK_KEY struct{}

type IP_MARK_KEY struct{}

func (IP_MARK_KEY) String() string { return "IP" }

type ForceModeKey struct{}

type Shunt struct {
	resolveProxy bool
	modifiedTime int64

	config *bypass.BypassConfig
	mapper *mapper.Combine[bypass.ModeEnum]
	mu     sync.RWMutex

	Opts

	tags []string
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
		mapper: mapper.NewMapper[bypass.ModeEnum](),
		config: &bypass.BypassConfig{
			Tcp: bypass.Mode_bypass,
			Udp: bypass.Mode_bypass,
		},
		Opts: opt,
	}
}

func (s *Shunt) Update(c *pc.Setting) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.resolveProxy = c.Dns.ResolveRemoteDomain

	modifiedTime := s.modifiedTime
	if stat, err := os.Stat(c.Bypass.BypassFile); err == nil {
		modifiedTime = stat.ModTime().Unix()
	}

	diff := (s.config == nil && c != nil) || s.config.BypassFile != c.Bypass.BypassFile || s.modifiedTime != modifiedTime

	s.config = c.Bypass

	if diff {
		s.mapper.Clear() //nolint:errcheck
		s.tags = nil
		s.modifiedTime = modifiedTime
		rangeRule(s.config.BypassFile, func(s1 string, s2 bypass.ModeEnum) {
			s.mapper.Insert(s1, s2)
			if s2.GetTag() != "" {
				s.tags = append(s.tags, s2.GetTag())
			}
		})
	}

	for _, v := range c.Bypass.CustomRuleV3 {
		mark := v.ToModeEnum()

		if mark.GetTag() != "" {
			s.tags = append(s.tags, mark.GetTag())
		}

		for _, hostname := range v.Hostname {
			s.mapper.Insert(hostname, mark)
		}
	}
}

func (s *Shunt) Tags() []string { return s.tags }

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

func (s *Shunt) dispatch(ctx context.Context, networkMode bypass.Mode, host netapi.Address) (bypass.Mode, netapi.Address) {
	// get mode from upstream specified

	store := netapi.StoreFromContext(ctx)

	mode, ok := netapi.Get[bypass.Mode](ctx, ForceModeKey{})
	if !ok {
		mode = bypass.Mode_bypass
	}

	if mode == bypass.Mode_bypass && networkMode != bypass.Mode_bypass {
		// get mode from network(tcp/udp) rule
		mode = networkMode
	} else {
		// get mode from bypass rule
		host.WithResolver(s.resolver(s.DefaultMode), true)
		fields := s.mapper.SearchWithDefault(ctx, host, s.DefaultMode)
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
	host.WithResolver(s.resolver(mode), true)

	if s.resolveProxy && host.Type() == netapi.DOMAIN && mode == bypass.Mode_proxy {
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
	host.WithResolver(mapper.SkipResolve, true)
	return s.resolver(s.mapper.SearchWithDefault(ctx, host, s.DefaultMode).Mode())
}

func (f *Shunt) LookupIP(ctx context.Context, domain string) ([]net.IP, error) {
	return f.Resolver(ctx, domain).LookupIP(ctx, domain)
}
func (f *Shunt) Record(ctx context.Context, domain string, t dnsmessage.Type) ([]net.IP, uint32, error) {
	return f.Resolver(ctx, domain).Record(ctx, domain, t)
}
func (f *Shunt) Do(ctx context.Context, addr string, b []byte) ([]byte, error) {
	return f.Resolver(ctx, addr).Do(ctx, addr, b)
}
func (f *Shunt) Close() error { return nil }

package shunt

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/mapper"
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
	resolveProxy     bool
	bypassModifyTime int64

	config *bypass.Config
	mapper *mapper.Combine[bypass.ModeEnum]
	mu     sync.RWMutex

	Opts

	tags []string
}

type Opts struct {
	DirectDialer   proxy.Proxy
	DirectResolver dns.DNS
	ProxyDialer    proxy.Proxy
	ProxyResolver  dns.DNS
	BlockDialer    proxy.Proxy
	BLockResolver  dns.DNS
	DefaultMode    bypass.Mode
}

func NewShunt(opt Opts) *Shunt {
	if opt.DefaultMode != bypass.Mode_block && opt.DefaultMode != bypass.Mode_direct && opt.DefaultMode != bypass.Mode_proxy {
		opt.DefaultMode = bypass.Mode_proxy
	}

	return &Shunt{
		mapper: mapper.NewMapper[bypass.ModeEnum](),
		config: &bypass.Config{
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

	modifiedTime := s.bypassModifyTime
	if stat, err := os.Stat(c.Bypass.BypassFile); err == nil {
		modifiedTime = stat.ModTime().Unix()
	}

	diff := (s.config == nil && c != nil) || s.config.BypassFile != c.Bypass.BypassFile || s.bypassModifyTime != modifiedTime

	s.config = c.Bypass

	if diff {
		s.mapper.Clear()
		s.tags = nil
		s.bypassModifyTime = modifiedTime
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

func (s *Shunt) Conn(ctx context.Context, host proxy.Address) (net.Conn, error) {
	mode, host := s.dispatch(ctx, s.config.Tcp, host)

	conn, err := s.dialer(mode).Conn(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	return conn, nil
}

func (s *Shunt) PacketConn(ctx context.Context, host proxy.Address) (net.PacketConn, error) {
	mode, host := s.dispatch(ctx, s.config.Udp, host)

	conn, err := s.dialer(mode).PacketConn(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	return conn, nil
}

func (s *Shunt) Dispatch(ctx context.Context, host proxy.Address) (proxy.Address, error) {
	_, addr := s.dispatch(ctx, bypass.Mode_bypass, host)
	return addr, nil
}

func (s *Shunt) dispatch(ctx context.Context, networkMode bypass.Mode, host proxy.Address) (bypass.Mode, proxy.Address) {
	// get mode from upstream specified
	mode := proxy.Value(host, ForceModeKey{}, bypass.Mode_bypass)

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
			host.WithValue(node.TagKey{}, tag)
		}

		if fields.GetResolveStrategy() == bypass.ResolveStrategy_prefer_ipv6 {
			host.WithValue(proxy.PreferIPv6{}, true)
		}
	}

	host.WithValue(modeMarkKey{}, mode)
	host.WithResolver(s.resolver(mode), true)

	if s.resolveProxy && host.Type() == proxy.DOMAIN && mode == bypass.Mode_proxy {
		// resolve proxy domain if resolveRemoteDomain enabled
		ip, err := host.IP(ctx)
		if err == nil {
			host.WithValue(DOMAIN_MARK_KEY{}, host.String())
			host = host.OverrideHostname(ip.String())
			host.WithValue(IP_MARK_KEY{}, host.String())
		} else {
			log.Warn("resolve remote domain failed", "err", err)
		}
	}

	return mode, host
}

func (s *Shunt) dialer(m bypass.Mode) proxy.Proxy {
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

func (s *Shunt) resolver(m bypass.Mode) dns.DNS {
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

var skipResolve = dns.NewErrorDNS(func(domain string) error { return mapper.ErrSkipResolve })

func (s *Shunt) Resolver(ctx context.Context, domain string) dns.DNS {
	host := proxy.ParseAddressPort(0, domain, proxy.EmptyPort)
	host.WithResolver(skipResolve, true)
	return s.resolver(s.mapper.SearchWithDefault(ctx, host, s.DefaultMode).Mode())
}

func (f *Shunt) LookupIP(ctx context.Context, domain string) ([]net.IP, error) {
	return f.Resolver(ctx, domain).LookupIP(ctx, domain)
}
func (f *Shunt) Record(ctx context.Context, domain string, t dnsmessage.Type) (dns.IPRecord, error) {
	return f.Resolver(ctx, domain).Record(ctx, domain, t)
}
func (f *Shunt) Do(ctx context.Context, addr string, b []byte) ([]byte, error) {
	return f.Resolver(ctx, addr).Do(ctx, addr, b)
}
func (f *Shunt) Close() error { return nil }

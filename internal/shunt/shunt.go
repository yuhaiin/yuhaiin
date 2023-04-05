package shunt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/mapper"
	"github.com/Asutorufa/yuhaiin/pkg/net/resolver"
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
	resolveRemoteDomain  bool
	bypassFileModifyTime int64
	defaultMode          bypass.Mode
	config               *bypass.Config
	mapper               *mapper.Combine[bypass.ModeEnum]
	mu                   sync.RWMutex
	modeStore            map[bypass.Mode]Mode

	tags []string
}

type Mode struct {
	Default  bool
	Mode     bypass.Mode
	Dialer   proxy.Proxy
	Resolver dns.DNS
}

func NewShunt(modes []Mode) *Shunt {
	s := &Shunt{
		mapper: mapper.NewMapper[bypass.ModeEnum](),
		config: &bypass.Config{
			Tcp: bypass.Mode_bypass,
			Udp: bypass.Mode_bypass,
		},
		modeStore: make(map[bypass.Mode]Mode, len(bypass.Mode_value)),
	}

	for _, mode := range modes {
		s.modeStore[mode.Mode] = mode
		if mode.Default {
			s.defaultMode = mode.Mode
		}
	}

	return s
}

func (s *Shunt) Update(c *pc.Setting) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.resolveRemoteDomain = c.Dns.ResolveRemoteDomain

	modifiedTime := s.bypassFileModifyTime
	if stat, err := os.Stat(c.Bypass.BypassFile); err == nil {
		modifiedTime = stat.ModTime().Unix()
	}

	diff := (s.config == nil && c != nil) || s.config.BypassFile != c.Bypass.BypassFile || s.bypassFileModifyTime != modifiedTime

	s.config = c.Bypass

	if diff {
		s.mapper.Clear()
		s.tags = nil
		s.bypassFileModifyTime = modifiedTime
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
	host, mode := s.bypass(ctx, s.config.Tcp, host)

	conn, err := mode.Dialer.Conn(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	return conn, nil
}

func (s *Shunt) PacketConn(ctx context.Context, host proxy.Address) (net.PacketConn, error) {
	host, mode := s.bypass(ctx, s.config.Udp, host)

	conn, err := mode.Dialer.PacketConn(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	return conn, nil
}

var errMode = Mode{
	Mode:     bypass.Mode(-1),
	Dialer:   proxy.NewErrProxy(errors.New("can't find mode")),
	Resolver: dns.NewErrorDNS(func(domain string) error { return errors.New("can't find mode") }),
}

func (s *Shunt) Dispatch(ctx context.Context, host proxy.Address) (proxy.Address, error) {
	addr, _ := s.bypass(ctx, bypass.Mode_bypass, host)
	return addr, nil
}

func (s *Shunt) bypass(ctx context.Context, networkMode bypass.Mode, host proxy.Address) (proxy.Address, Mode) {
	// get mode from upstream specified
	mode := proxy.Value(host, ForceModeKey{}, bypass.Mode_bypass)

	if mode == bypass.Mode_bypass {
		// get mode from network(tcp/udp) rule
		mode = networkMode
	}

	if mode == bypass.Mode_bypass {
		// get mode from bypass rule
		host.WithResolver(s.resolver(s.defaultMode), true)
		fields := s.search(ctx, host)
		mode = fields.Mode()

		// get tag from bypass rule
		if tag := fields.GetTag(); len(tag) != 0 {
			host.WithValue(node.TagKey{}, tag)
		}

		if fields.GetResolveStrategy() == bypass.ResolveStrategy_prefer_ipv6 {
			host.WithValue(proxy.PreferIPv6{}, true)
		}
	}

	m, ok := s.modeStore[mode]
	if !ok {
		m = errMode
	}

	host.WithValue(modeMarkKey{}, mode)
	host.WithResolver(m.Resolver, true)

	if !s.resolveRemoteDomain || host.Type() != proxy.DOMAIN || mode != bypass.Mode_proxy {
		return host, m
	}

	// resolve proxy domain if resolveRemoteDomain enabled
	ip, err := host.IP(ctx)
	if err == nil {
		host.WithValue(DOMAIN_MARK_KEY{}, host.String())
		host = host.OverrideHostname(ip.String())
		host.WithValue(IP_MARK_KEY{}, host.String())
	} else {
		log.Warningln("resolve remote domain failed: %w", err)
	}

	return host, m
}

var skipResolve = dns.NewErrorDNS(func(domain string) error { return mapper.ErrSkipResolveDomain })

func (s *Shunt) Resolver(ctx context.Context, domain string) dns.DNS {
	host := proxy.ParseAddressPort(0, domain, proxy.EmptyPort)
	host.WithResolver(skipResolve, true)
	return s.resolver(s.search(ctx, host))
}

func (s *Shunt) resolver(m bypass.ModeEnum) dns.DNS {
	d, ok := s.modeStore[m.Mode()]
	if ok {
		return d.Resolver
	}

	return resolver.Bootstrap
}

func (s *Shunt) search(ctx context.Context, host proxy.Address) bypass.ModeEnum {
	m, ok := s.mapper.Search(ctx, host)
	if !ok {
		return s.defaultMode
	}

	return m
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

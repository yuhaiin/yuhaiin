package shunt

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	imapper "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/mapper"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/mapper"
	"github.com/Asutorufa/yuhaiin/pkg/net/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	pconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
)

type MODE_MARK_KEY struct{}

func (MODE_MARK_KEY) String() string { return "MODE" }

type DOMAIN_MARK_KEY struct{}

type IP_MARK_KEY struct{}

func (IP_MARK_KEY) String() string { return "IP" }

type ForceModeKey struct{}

type shunt struct {
	resolveRemoteDomain bool
	defaultMode         bypass.Mode
	config              *bypass.Config
	mapper              imapper.Mapper[string, proxy.Address, bypass.ModeEnum]
	lock                sync.RWMutex
	modeStore           map[bypass.Mode]Mode
}

type Mode struct {
	Default  bool
	Mode     bypass.Mode
	Dialer   proxy.Proxy
	Resolver dns.DNS
}

func NewShunt(modes []Mode) proxy.DialerResolverProxy {
	s := &shunt{
		mapper: mapper.NewMapper[bypass.ModeEnum](),
		config: &bypass.Config{
			Tcp:        bypass.Mode_bypass,
			Udp:        bypass.Mode_bypass,
			BypassFile: "",
		},
		modeStore: make(map[bypass.Mode]Mode),
	}

	for _, mode := range modes {
		s.modeStore[mode.Mode] = mode
		if mode.Default {
			s.defaultMode = mode.Mode
		}
	}

	return s
}

func (s *shunt) Update(c *pconfig.Setting) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.resolveRemoteDomain = c.Dns.ResolveRemoteDomain

	diff := (s.config == nil && c != nil) || s.config.BypassFile != c.Bypass.BypassFile
	s.config = c.Bypass

	if diff {
		s.mapper.Clear()
		rangeRule(s.config.BypassFile, func(s1 string, s2 bypass.ModeEnum) { s.mapper.Insert(s1, s2) })
	}

	for k, v := range c.Bypass.CustomRuleV2 {
		if v.Mode == bypass.Mode_proxy && len(v.Fields) != 0 {
			s.mapper.Insert(k, &field{v.Mode, v.Fields})
		} else {
			s.mapper.Insert(k, v.Mode)
		}
	}
}

func (s *shunt) Conn(host proxy.Address) (net.Conn, error) {
	host, mode := s.bypass(s.config.Tcp, host)

	conn, err := mode.Dialer.Conn(host)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	return conn, err
}

func (s *shunt) PacketConn(host proxy.Address) (net.PacketConn, error) {
	host, mode := s.bypass(s.config.Udp, host)

	conn, err := mode.Dialer.PacketConn(host)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	return conn, err
}

var errMode = Mode{
	Mode:     bypass.Mode(-1),
	Dialer:   proxy.NewErrProxy(errors.New("can't find mode")),
	Resolver: dns.NewErrorDNS(errors.New("can't find mode")),
}

func (s *shunt) bypass(networkMode bypass.Mode, host proxy.Address) (proxy.Address, Mode) {
	mode := proxy.Value(host, ForceModeKey{}, bypass.Mode_bypass)

	if mode == bypass.Mode_bypass {
		mode = networkMode
	}

	if mode == bypass.Mode_bypass {
		host.WithResolver(s.loadResolver(s.defaultMode), true)
		fields := s.search(host)
		mode = fields.Mode()

		v, ok := fields.Value("tag")
		if ok {
			host.WithValue(node.TagKey{}, v)
		}
	}

	m, ok := s.modeStore[mode]
	if !ok {
		m = errMode
	}

	host.WithValue(MODE_MARK_KEY{}, mode)
	host.WithResolver(m.Resolver, true)

	if !s.resolveRemoteDomain || host.Type() != proxy.DOMAIN || mode != bypass.Mode_proxy {
		return host, m
	}

	ip, err := host.IP()
	if err == nil {
		host.WithValue(DOMAIN_MARK_KEY{}, host.String())
		host = host.OverrideHostname(ip.String())
		host.WithValue(IP_MARK_KEY{}, host.String())
	} else {
		log.Warningln("resolve remote domain failed: %w", err)
	}

	return host, m
}

var skipResolve = dns.NewErrorDNS(imapper.ErrSkipResolveDomain)

func (s *shunt) Resolver(host proxy.Address) dns.DNS {
	host.WithResolver(skipResolve, true)
	return s.loadResolver(s.search(host))
}

func (s *shunt) loadResolver(m bypass.ModeEnum) dns.DNS {
	d, ok := s.modeStore[m.Mode()]
	if ok {
		return d.Resolver
	}

	return resolver.Bootstrap
}

func (s *shunt) search(host proxy.Address) bypass.ModeEnum {
	m, ok := s.mapper.Search(host)
	if !ok {
		return s.defaultMode
	}

	return m
}

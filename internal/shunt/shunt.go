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
	pconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
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
	mapper              imapper.Mapper[string, proxy.Address, bypass.Mode]
	lock                sync.RWMutex
	modeStore           syncmap.SyncMap[bypass.Mode, Mode]
}

type Mode struct {
	Default  bool
	Mode     bypass.Mode
	Dialer   proxy.Proxy
	Resolver dns.DNS
}

func NewShunt(modes []Mode) proxy.DialerResolverProxy {
	s := &shunt{
		mapper: mapper.NewMapper[bypass.Mode](),
		config: &bypass.Config{
			Tcp:        bypass.Mode_bypass,
			Udp:        bypass.Mode_bypass,
			BypassFile: "",
		},
	}

	for _, mode := range modes {
		s.AddMode(mode)
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
		rangeRule(s.config.BypassFile, func(s1 string, s2 field) { s.mapper.Insert(s1, bypass.Mode(bypass.Mode_value[s2.mode])) })
	}

	for k, v := range c.Bypass.CustomRule {
		s.mapper.Insert(k, v)
	}
}

func (s *shunt) AddMode(m Mode) {
	s.modeStore.Store(m.Mode, m)
	if m.Default {
		s.defaultMode = m.Mode
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
		mode = s.search(host)
	}

	m, ok := s.modeStore.Load(mode)
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

func (s *shunt) loadResolver(m bypass.Mode) dns.DNS {
	d, ok := s.modeStore.Load(m)
	if ok {
		return d.Resolver
	}

	return resolver.Bootstrap
}

func (s *shunt) search(host proxy.Address) bypass.Mode {
	m, ok := s.mapper.Search(host)
	if !ok {
		return s.defaultMode
	}

	return m
}

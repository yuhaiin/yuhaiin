package shunt

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"
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

type mode struct {
	dialer proxy.Proxy
	dns    dns.DNS
}

type shunt struct {
	mapper imapper.Mapper[string, proxy.Address, bypass.Mode]

	config              *bypass.Config
	resolveRemoteDomain bool
	lock                sync.RWMutex

	modeStore   syncmap.SyncMap[bypass.Mode, mode]
	defaultMode bypass.Mode
}

type Mode struct {
	Mode     bypass.Mode
	Default  bool
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
		s.AddMode(mode.Mode, mode.Default, mode.Dialer, mode.Resolver)
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
		if err := s.refresh(); err != nil {
			log.Errorln("refresh bypass file failed:", err)
		}
	}

	for k, v := range c.Bypass.CustomRule {
		s.mapper.Insert(k, v)
	}
}

func (s *shunt) refresh() error {
	f := getBypassData(s.config.BypassFile)
	defer f.Close()

	s.mapper.Clear()

	br := bufio.NewScanner(f)
	for {
		if !br.Scan() {
			break
		}

		a := br.Bytes()

		i := bytes.IndexByte(a, '#')
		if i != -1 {
			a = a[:i]
		}

		i = bytes.IndexByte(a, ' ')
		if i == -1 {
			continue
		}

		c, b := a[:i], a[i+1:]

		if len(c) != 0 && len(b) != 0 {
			s.mapper.Insert(strings.ToLower(string(c)), bypass.Mode(bypass.Mode_value[strings.ToLower(string(b))]))
		}
	}
	return nil
}

func (s *shunt) AddMode(m bypass.Mode, defaultMode bool, p proxy.Proxy, resolver dns.DNS) {
	s.modeStore.Store(m, mode{p, resolver})
	if defaultMode {
		s.defaultMode = m
	}
}

func (s *shunt) Conn(host proxy.Address) (net.Conn, error) {
	host, mode, ok := s.getMark(s.config.Tcp, host)
	if !ok {
		return nil, fmt.Errorf("not found mode for %v", host)
	}

	conn, err := mode.dialer.Conn(host)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	return conn, err
}

func (s *shunt) PacketConn(host proxy.Address) (net.PacketConn, error) {
	host, mode, ok := s.getMark(s.config.Udp, host)
	if !ok {
		return nil, fmt.Errorf("not found mode for %v", host)
	}

	conn, err := mode.dialer.PacketConn(host)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	return conn, err
}

func (s *shunt) getMark(networkMode bypass.Mode, host proxy.Address) (proxy.Address, mode, bool) {
	mode := proxy.GetMark(host, ForceModeKey{}, bypass.Mode_bypass)

	if mode == bypass.Mode_bypass {
		mode = networkMode
	}

	if mode == bypass.Mode_bypass {
		rv := resolver.Bootstrap
		r, ok := s.modeStore.Load(s.defaultMode)
		if ok {
			rv = r.dns
		}

		host.WithResolver(rv, true)
		mode, ok = s.mapper.Search(host)
		if !ok {
			mode = s.defaultMode
		}
	}

	m, ok := s.modeStore.Load(mode)
	if !ok {
		return host, m, ok
	}

	host.WithValue(MODE_MARK_KEY{}, mode)
	host.WithResolver(m.dns, true)

	if !s.resolveRemoteDomain || host.Type() != proxy.DOMAIN || mode != bypass.Mode_proxy {
		return host, m, ok
	}

	ip, err := host.IP()
	if err == nil {
		host.WithValue(DOMAIN_MARK_KEY{}, host.String())
		host = host.OverrideHostname(ip.String())
		host.WithValue(IP_MARK_KEY{}, host.String())
	} else {
		log.Warningln("resolve remote domain failed: %w", err)
	}

	return host, m, ok
}

var resolverResolver = dns.NewErrorDNS(imapper.ErrSkipResolveDomain)

func (s *shunt) Resolver(host proxy.Address) dns.DNS {
	host.WithResolver(resolverResolver, true)
	m, ok := s.mapper.Search(host)
	if !ok {
		m = s.defaultMode
	}
	d, ok := s.modeStore.Load(m)
	if ok {
		return d.dns
	}
	return resolver.Bootstrap
}

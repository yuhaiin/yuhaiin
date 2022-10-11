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
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type mode struct {
	dialer proxy.Proxy
	dns    dns.DNS
}

type shunt struct {
	mapper imapper.Mapper[string, proxy.Address, protoconfig.BypassMode]

	config *protoconfig.Bypass
	lock   sync.RWMutex

	modeStore   syncmap.SyncMap[protoconfig.BypassMode, mode]
	defaultMode protoconfig.BypassMode
}

type Mode struct {
	Mode     protoconfig.BypassMode
	Default  bool
	Dialer   proxy.Proxy
	Resolver dns.DNS
}

func NewShunt(modes []Mode) proxy.DialerResolverProxy {
	s := &shunt{
		mapper: mapper.NewMapper[protoconfig.BypassMode](),
		config: &protoconfig.Bypass{
			Tcp:        protoconfig.Bypass_bypass,
			Udp:        protoconfig.Bypass_bypass,
			BypassFile: "",
		},
	}

	for _, mode := range modes {
		s.AddMode(mode.Mode, mode.Default, mode.Dialer, mode.Resolver)
	}

	return s
}

func (s *shunt) Update(c *protoconfig.Setting) {
	s.lock.Lock()
	defer s.lock.Unlock()

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
			s.mapper.Insert(strings.ToLower(string(c)), protoconfig.BypassMode(protoconfig.BypassMode_value[strings.ToLower(string(b))]))
		}
	}
	return nil
}

func (s *shunt) AddMode(m protoconfig.BypassMode, defaultMode bool, p proxy.Proxy, resolver dns.DNS) {
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

func (s *shunt) getMark(networkMode protoconfig.BypassMode, host proxy.Address) (proxy.Address, mode, bool) {
	forceMode := proxy.GetMark(host, ForceModeKey{}, protoconfig.Bypass_bypass)

	mode := forceMode

	if forceMode == protoconfig.Bypass_bypass {
		switch networkMode {
		case protoconfig.Bypass_bypass:
			rv := resolver.Bootstrap
			r, ok := s.modeStore.Load(s.defaultMode)
			if ok {
				rv = r.dns
			}

			host.WithResolver(rv)
			mode, ok = s.mapper.Search(host)
			if !ok {
				mode = s.defaultMode
			}
		default:
			mode = networkMode
		}
	}

	m, ok := s.modeStore.Load(mode)
	if ok {
		host.WithValue(MODE_MARK_KEY{}, mode)
		host.WithResolver(m.dns)
	}

	return host, m, ok
}

var resolverResolver = dns.NewErrorDNS(imapper.ErrSkipResolveDomain)

func (s *shunt) Resolver(host proxy.Address) dns.DNS {
	host.WithResolver(resolverResolver)
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

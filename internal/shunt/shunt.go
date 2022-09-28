package shunt

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
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

func writeDefaultBypassData(target string) error {
	_, err := os.Stat(target)
	if err == nil {
		return nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat bypass file failed: %w", err)
	}

	err = os.MkdirAll(filepath.Dir(target), os.ModePerm)
	if err != nil {
		return fmt.Errorf("create bypass dir failed: %w", err)
	}

	gr, err := gzip.NewReader(bytes.NewReader(BYPASS_DATA))
	if err != nil {
		return fmt.Errorf("create gzip reader failed: %w", err)
	}
	defer gr.Close()

	data, err := io.ReadAll(gr)
	if err != nil {
		return fmt.Errorf("read gzip data failed: %w", err)
	}

	return os.WriteFile(target, data, os.ModePerm)
}

type shunt struct {
	mapper imapper.Mapper[string, proxy.Address, protoconfig.BypassMode]

	config *protoconfig.Bypass
	lock   sync.RWMutex

	modeStore syncmap.SyncMap[protoconfig.BypassMode, struct {
		dialer proxy.Proxy
		dns    dns.DNS
	}]
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
	err := writeDefaultBypassData(s.config.BypassFile)
	if err != nil {
		return fmt.Errorf("copy bypass file failed: %w", err)
	}

	f, err := os.Open(s.config.BypassFile)
	if err != nil {
		return fmt.Errorf("open bypass file failed: %w", err)
	}
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
	s.modeStore.Store(m, struct {
		dialer proxy.Proxy
		dns    dns.DNS
	}{p, resolver})
	if defaultMode {
		s.defaultMode = m
	}
}

func (s *shunt) Conn(host proxy.Address) (net.Conn, error) {
	m := s.getMark(s.config.Tcp, host)
	mode, ok := s.modeStore.Load(m)
	if !ok {
		return nil, fmt.Errorf("not found mode for %d", m)
	}

	host.WithResolver(mode.dns)
	host.AddMark(MODE_MARK_KEY{}, m)

	conn, err := mode.dialer.Conn(host)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	return conn, err
}

func (s *shunt) PacketConn(host proxy.Address) (net.PacketConn, error) {
	m := s.getMark(s.config.Udp, host)

	mode, ok := s.modeStore.Load(m)
	if !ok {
		return nil, fmt.Errorf("not found mode for %d", m)
	}

	host.WithResolver(mode.dns)
	host.AddMark(MODE_MARK_KEY{}, m)

	conn, err := mode.dialer.PacketConn(host)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	return conn, err
}

func (s *shunt) getMark(mode protoconfig.BypassMode, host proxy.Address) protoconfig.BypassMode {
	forceMode := proxy.GetMark(host, ForceModeKey{}, protoconfig.Bypass_bypass)

	if forceMode != protoconfig.Bypass_bypass {
		return forceMode
	}

	if mode != protoconfig.Bypass_bypass {
		return mode
	}

	rv := resolver.Bootstrap
	r, ok := s.modeStore.Load(s.defaultMode)
	if ok {
		rv = r.dns
	}

	host.WithResolver(rv)
	m, ok := s.mapper.Search(host)
	if !ok {
		m = s.defaultMode
	}

	return m
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

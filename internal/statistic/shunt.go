package statistic

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	imapper "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/mapper"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/mapper"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils/resolver"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

//go:embed statics/bypass.gz
var BYPASS_DATA []byte

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

	data, err := ioutil.ReadAll(gr)
	if err != nil {
		return fmt.Errorf("read gzip data failed: %w", err)
	}

	return ioutil.WriteFile(target, data, os.ModePerm)
}

var (
	MODE_MARK = "MODE_MARK"
)

type shunt struct {
	mapper imapper.Mapper[string, proxy.Address, int64]

	config *protoconfig.Bypass
	lock   sync.RWMutex

	conns conns

	rule
	modeStore syncmap.SyncMap[int64, struct {
		dialer proxy.Proxy
		dns    dns.DNS
	}]
	defaultMode int64
}

func newShunt(resolver dns.DNS, conns conns) *shunt {
	return &shunt{
		mapper: mapper.NewMapper[int64](resolver),
		conns:  conns,
		config: &protoconfig.Bypass{
			Tcp:        protoconfig.Bypass_bypass,
			Udp:        protoconfig.Bypass_bypass,
			BypassFile: "",
		},
	}
}

func (s *shunt) Update(c *protoconfig.Setting) {
	s.lock.Lock()
	defer s.lock.Unlock()

	diff := (s.config == nil && c != nil) || s.config.BypassFile != c.Bypass.BypassFile
	s.config = c.Bypass

	if diff {
		s.mapper.Clear()
		if err := s.refresh(); err != nil {
			log.Println("refresh bypass file failed:", err)
		}
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
			s.Insert(string(c), string(b))
		}
	}
	return nil
}

func (s *shunt) Insert(c, mode string) { s.mapper.Insert(c, s.rule.GetID(mode)) }

func (s *shunt) match(addr proxy.Address, resolveDomain bool) int64 {
	r := s.mapper
	if !resolveDomain {
		if z, ok := s.mapper.(interface {
			Domain() imapper.Mapper[string, proxy.Address, int64]
		}); ok {
			r = z.Domain()
		}
	}
	if m, ok := r.Search(addr); ok {
		return m
	}

	return s.defaultMode
}

func (s *shunt) AddMode(m string, defaultMode bool, p proxy.Proxy, resolver dns.DNS) (id int64) {
	id = s.rule.GetID(m)
	s.modeStore.Store(id, struct {
		dialer proxy.Proxy
		dns    dns.DNS
	}{p, resolver})
	if defaultMode {
		s.defaultMode = id
	}

	return id
}

func (s *shunt) GetDialer(m string) proxy.Proxy {
	d, ok := s.modeStore.Load(s.rule.GetID(m))
	if ok {
		return d.dialer
	}
	return proxy.NewErrProxy(fmt.Errorf("no dialer for mode: %s", m))
}

func (s *shunt) Conn(host proxy.Address) (net.Conn, error) {
	m, mark := s.getMark(s.config.Tcp, host)
	mode, ok := s.modeStore.Load(m)
	if !ok {
		return nil, fmt.Errorf("not found mode for %d", m)
	}

	host.WithResolver(mode.dns)
	host.AddMark(MODE_MARK, mark)

	conn, err := mode.dialer.Conn(host)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	return s.conns.AddConn(conn, host), nil
}

func (s *shunt) getMark(mode protoconfig.BypassMode, host proxy.Address) (int64, string) {
	if mode != protoconfig.Bypass_bypass {
		mark := mode.String()
		return s.rule.GetID(mark), mark
	}
	m := s.match(host, true)
	return m, s.rule.GetMode(m)
}

func (s *shunt) PacketConn(host proxy.Address) (net.PacketConn, error) {
	m, mark := s.getMark(s.config.Udp, host)
	mode, ok := s.modeStore.Load(m)
	if !ok {
		return nil, fmt.Errorf("not found mode for %d", m)
	}

	host.WithResolver(mode.dns)
	host.AddMark(MODE_MARK, mark)

	conn, err := mode.dialer.PacketConn(host)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	return s.conns.AddPacketConn(conn, host), nil
}

func (s *shunt) GetResolver(host proxy.Address) (dns.DNS, int64) {
	m := s.match(host, false)
	d, ok := s.modeStore.Load(m)
	if ok {
		return d.dns, m
	}
	return resolver.Bootstrap, m
}

type rule struct {
	id        idGenerater
	mapping   syncmap.SyncMap[string, int64]
	idMapping syncmap.SyncMap[int64, string]
}

func (r *rule) GetID(s string) int64 {
	s = strings.ToUpper(s)
	if v, ok := r.mapping.Load(s); ok {
		return v
	}
	id := r.id.Generate()
	r.mapping.Store(s, id)
	r.idMapping.Store(id, s)
	return id
}

func (r *rule) GetMode(id int64) string {
	if v, ok := r.idMapping.Load(id); ok {
		return v
	}
	return ""
}

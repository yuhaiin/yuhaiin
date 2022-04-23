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
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/mapper"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

// go:embed statics/bypass.gz
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

type MODE string

var (
	OTHERS MODE = "OTHERS"
	BLOCK  MODE = "BLOCK"
	DIRECT MODE = "DIRECT"
	PROXY  MODE = "PROXY"
	MAX    MODE = "MAX"

	UNKNOWN MODE = "UNKNOWN"
)

func (m MODE) String() string {
	return string(m)
}

var Mode = map[string]*MODE{
	"direct": &DIRECT,
	// "proxy":  PROXY,
	"block": &BLOCK,
}

type Shunt struct {
	file string

	remote *protoconfig.Dns

	mapper *mapper.Mapper[*MODE]
	bypass bool

	dialer   proxy.Proxy
	fileLock sync.RWMutex
}

func newShunt(dialer proxy.Proxy) *Shunt {
	return &Shunt{
		dialer: dialer,
		mapper: mapper.NewMapper[*MODE](nil),
	}
}

func (s *Shunt) Update(c *protoconfig.Setting) {
	if s.file == "" || s.file != c.Bypass.BypassFile {
		s.fileLock.Lock()
		s.file = c.Bypass.BypassFile
		s.fileLock.Unlock()

		if err := s.Refresh(); err != nil {
			log.Println("refresh bypass file failed:", err)
		}
	}

	if s.remote == nil || diffDNS(s.remote, c.Dns.Remote) {
		s.mapper.SetLookup(getDNS(c.Dns.Remote, s.dialer).LookupIP)
		s.mapper.Insert(getDnsConfig(c.Dns.Remote))
		s.remote = c.Dns.Remote
	}

	s.bypass = c.Bypass.Enabled
}

func (s *Shunt) Refresh() error {
	s.fileLock.RLock()
	defer s.fileLock.RUnlock()

	err := writeDefaultBypassData(s.file)
	if err != nil {
		return fmt.Errorf("copy bypass file failed: %w", err)
	}

	f, err := os.Open(s.file)
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

		if bytes.Equal(b, []byte{}) {
			continue
		}

		s.mapper.Insert(string(c), Mode[strings.ToLower(*(*string)(unsafe.Pointer(&b)))])
	}
	return nil
}

func (s *Shunt) Get(domain string) MODE {
	host, _, err := net.SplitHostPort(domain)
	if err == nil {
		domain = host
	}

	if !s.bypass {
		return PROXY
	}
	m, _ := s.mapper.Search(domain)
	if m == nil {
		return PROXY
	}
	return *m
}

func getDnsConfig(dc *protoconfig.Dns) (string, *MODE) {
	host := dc.Host
	if dc.Type == protoconfig.Dns_doh {
		i := strings.IndexByte(dc.Host, '/')
		if i != -1 {
			host = dc.Host[:i] // remove doh path
		}
	}

	h, _, err := net.SplitHostPort(host)
	if err == nil {
		host = h
	}

	mode := &PROXY
	if !dc.Proxy {
		mode = &DIRECT
	}

	return host, mode
}

func diffDNS(old, new *protoconfig.Dns) bool {
	return old.Host != new.Host ||
		old.Type != new.Type ||
		old.Subnet != new.Subnet || old.Proxy != new.Proxy
}

func getDNS(dc *protoconfig.Dns, proxy proxy.Proxy) dns.DNS {
	_, subnet, err := net.ParseCIDR(dc.Subnet)
	if err != nil {
		p := net.ParseIP(dc.Subnet)
		if p != nil { // no mask
			var mask net.IPMask
			if p.To4() == nil { // ipv6
				mask = net.IPMask{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}
			} else {
				mask = net.IPMask{255, 255, 255, 255}
			}

			subnet = &net.IPNet{IP: p, Mask: mask}
		}
	}

	if !dc.Proxy {
		proxy = nil
	}

	switch dc.Type {
	case protoconfig.Dns_doh:
		return dns.NewDoH(dc.Host, subnet, proxy)
	case protoconfig.Dns_dot:
		return dns.NewDoT(dc.Host, subnet, proxy)
	case protoconfig.Dns_tcp:
		fallthrough
	case protoconfig.Dns_udp:
		fallthrough
	default:
		return dns.NewDNS(dc.Host, subnet, proxy)
	}
}

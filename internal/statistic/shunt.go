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
	"google.golang.org/protobuf/proto"
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
	mapper *mapper.Mapper[*MODE]

	config *protoconfig.Bypass
	lock   sync.RWMutex

	resolver *remoteResolver
}

func newShunt(dialer proxy.Proxy) *Shunt {
	resolver := newRemoteResolver(dialer)
	return &Shunt{
		mapper:   mapper.NewMapper[*MODE](resolver.LookupIP),
		config:   &protoconfig.Bypass{Enabled: true, BypassFile: ""},
		resolver: resolver,
	}
}

func (s *Shunt) Update(c *protoconfig.Setting) {
	s.lock.Lock()
	defer s.lock.Unlock()

	diff := !proto.Equal(s.config, c.Bypass)
	s.config = c.Bypass

	if !s.config.Enabled {
		s.mapper.Clear()
	}

	if diff && s.config.Enabled {
		if err := s.refresh(); err != nil {
			log.Println("refresh bypass file failed:", err)
		}
	}

	s.mapper.Insert(getDnsConfig(c.Dns.Remote))
	s.resolver.Update(c)
}

func (s *Shunt) refresh() error {
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

		if bytes.Equal(b, []byte{}) {
			continue
		}

		s.mapper.Insert(string(c), Mode[strings.ToLower(*(*string)(unsafe.Pointer(&b)))])
	}
	return nil
}

func (s *Shunt) Get(domain string) MODE {
	if !s.config.Enabled {
		return PROXY
	}

	host, _, err := net.SplitHostPort(domain)
	if err == nil {
		domain = host
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

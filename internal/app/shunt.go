package app

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/mapper"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

type MODE int

const (
	OTHERS MODE = 0
	BLOCK  MODE = 1
	DIRECT MODE = 2
	// PROXY  MODE = 3
	MAX MODE = 3
)

func (m MODE) String() string {
	switch m {
	case BLOCK:
		return "BLOCK"
	case DIRECT:
		return "DIRECT"
	default:
		return "PROXY"
	}
}

var Mode = map[string]MODE{
	"direct": DIRECT,
	// "proxy":  PROXY,
	"block": BLOCK,
}

func init() {
	defer runtime.GC()

	cache, err := os.UserCacheDir()
	if err != nil {
		log.Println("get user cache dir failed:", err)
		return
	}
	cache = filepath.Join(cache, "yuhaiin")
	err = os.MkdirAll(cache, os.ModePerm)
	if err != nil {
		log.Println("create cache dir failed:", err)
		return
	}
	err = ioutil.WriteFile(filepath.Join(cache, "bypass.conf"), bypassData, os.ModePerm)
	if err != nil {
		log.Println("write bypass file failed: %w", err)
	}
}

func copyBypassFile(target string) error {
	_, err := os.Stat(target)
	if errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(filepath.Dir(target), os.ModePerm)
	}
	if err != nil {
		return err
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return fmt.Errorf("get user cache dir failed: %w", err)
	}
	cache = filepath.Join(cache, "yuhaiin", "bypass.conf")
	_, err = os.Stat(cache)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("bypass file not found: %w", err)
	}

	source, err := os.Open(cache)
	if err != nil {
		return fmt.Errorf("open bypass file failed: %w", err)
	}
	defer source.Close()

	destination, err := os.Create(target)
	if err != nil {
		return fmt.Errorf("create bypass file failed: %w", err)
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}

type Shunt struct {
	file   string
	mapper *mapper.Mapper[MODE]

	p        proxy.Proxy
	fileLock sync.RWMutex
}

func WithProxy(p proxy.Proxy) func(*Shunt) {
	return func(s *Shunt) {
		s.p = p
	}
}

//NewShunt file: bypass file; lookup: domain resolver, can be nil
func NewShunt(conf *config.Config, opts ...func(*Shunt)) (*Shunt, error) {
	s := &Shunt{}

	for _, opt := range opts {
		opt(s)
	}

	s.mapper = mapper.NewMapper[MODE](nil)

	conf.AddObserverAndExec(func(current, old *config.Setting) bool {
		return current.Bypass.BypassFile != old.Bypass.BypassFile
	}, func(current *config.Setting) {
		if s.file == current.Bypass.BypassFile {
			return
		}
		s.fileLock.Lock()
		s.file = current.Bypass.BypassFile
		s.fileLock.Unlock()

		if err := s.RefreshMapping(); err != nil {
			log.Println("refresh bypass file failed:", err)
		}
	})

	conf.AddObserverAndExec(func(current, old *config.Setting) bool {
		return diffDNS(current.Dns.Remote, old.Dns.Remote)
	}, func(current *config.Setting) {
		s.mapper.SetLookup(getDNS(current.Dns.Remote, s.p).LookupIP)
		s.mapper.Insert(getDNSHostnameAndMode(current.Dns.Remote))
	})

	conf.AddExecCommand("RefreshMapping", func(*config.Setting) error {
		return s.RefreshMapping()
	})

	return s, nil
}

func (s *Shunt) RefreshMapping() error {
	s.fileLock.RLock()
	defer s.fileLock.RUnlock()

	_, err := os.Stat(s.file)
	if errors.Is(err, os.ErrNotExist) {
		err = copyBypassFile(s.file)
	}
	if err != nil {
		return err
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

		if len(a) <= 3 || a[0] == '#' {
			continue
		}

		i := bytes.IndexByte(a, ' ')
		if i == -1 {
			continue
		}

		c := a[:i]
		i2 := bytes.IndexByte(a[i+1:], ' ')
		var b []byte
		if i2 != -1 {
			b = a[i+1 : i2+i+1]
		} else {
			b = a[i+1:]
		}

		if bytes.Equal(b, []byte{}) {
			continue
		}

		s.mapper.Insert(string(c), Mode[strings.ToLower(*(*string)(unsafe.Pointer(&b)))])
	}
	return nil
}

func (s *Shunt) Get(domain string) MODE {
	m, _ := s.mapper.Search(domain)
	return m
}

func getDNSHostnameAndMode(dc *config.DNS) (string, MODE) {
	host := dc.Host
	if dc.Type == config.DNS_doh {
		i := strings.IndexByte(dc.Host, '/')
		if i != -1 {
			host = dc.Host[:i] // remove doh path
		}
	}

	h, _, err := net.SplitHostPort(host)
	if err == nil {
		host = h
	}

	mode := OTHERS
	if !dc.Proxy {
		mode = DIRECT
	}

	return host, mode
}

func diffDNS(old, new *config.DNS) bool {
	return old.Host != new.Host ||
		old.Type != new.Type ||
		old.Subnet != new.Subnet || old.Proxy != new.Proxy
}

func getDNS(dc *config.DNS, proxy proxy.Proxy) dns.DNS {
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
	case config.DNS_doh:
		return dns.NewDoH(dc.Host, subnet, proxy)
	case config.DNS_dot:
		return dns.NewDoT(dc.Host, subnet, proxy)
	case config.DNS_tcp:
		fallthrough
	case config.DNS_udp:
		fallthrough
	default:
		return dns.NewDNS(dc.Host, subnet, proxy)
	}
}

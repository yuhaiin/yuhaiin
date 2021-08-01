package app

import (
	"bufio"
	"bytes"
	_ "embed" //embed for bypass file
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/mapper"
)

//go:embed yuhaiin.conf
var bypassData []byte

func saveBypassData(filePath string) (err error) {
	err = os.MkdirAll(path.Dir(filePath), os.ModePerm)
	if err != nil {
		return fmt.Errorf("make dir all failed: %w", err)
	}

	err = ioutil.WriteFile(filePath, bypassData, os.ModePerm)
	if err != nil {
		return fmt.Errorf("write bypass file failed: %w", err)
	}

	return
}

type Shunt struct {
	file   string
	mapper *mapper.Mapper

	fileLock sync.RWMutex
}

//NewShunt file: bypass file; lookup: domain resolver, can be nil
func NewShunt(conf *config.Config) (*Shunt, error) {
	s := &Shunt{}

	err := conf.Exec(
		func(ss *config.Setting) error {
			s.file = ss.Bypass.BypassFile
			s.mapper = mapper.NewMapper(getDNS(ss.Dns.Remote).LookupIP)
			err := s.RefreshMapping()
			if err != nil {
				return fmt.Errorf("refresh mapping failed: %v", err)
			}
			return nil
		})
	if err != nil {
		return s, err
	}

	conf.AddObserver(func(current, old *config.Setting) {
		if current.Bypass.BypassFile != old.Bypass.BypassFile {
			err := s.SetFile(current.Bypass.BypassFile)
			if err != nil {
				log.Printf("shunt set file failed: %v", err)
			}
		}
	})

	conf.AddObserver(func(current, old *config.Setting) {
		if diffDNS(current.Dns.Remote, old.Dns.Remote) {
			s.mapper.SetLookup(getDNS(current.Dns.Remote).LookupIP)
		}
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
		err = saveBypassData(s.file)
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

	re, _ := regexp.Compile("^([^ ]+) +([^ ]+) *$") // already test that is right regular expression, so don't need to check error
	br := bufio.NewReader(f)
	for {
		a, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		if bytes.HasPrefix(a, []byte("#")) {
			continue
		}
		result := re.FindSubmatch(a)
		if len(result) != 3 {
			continue
		}
		mode := Mode[strings.ToLower(*(*string)(unsafe.Pointer(&result[2])))]
		if mode == OTHERS {
			continue
		}
		s.mapper.Insert(string(result[1]), mode)
	}
	return nil
}

func (s *Shunt) SetFile(f string) error {
	if s.file == f {
		return nil
	}
	s.fileLock.Lock()
	s.file = f
	s.fileLock.Unlock()

	return s.RefreshMapping()
}

func (s *Shunt) Get(domain string) MODE {
	x, _ := s.mapper.Search(domain).(MODE)
	return x
}

func diffDNS(old, new *config.DNS) bool {
	if old.Host != new.Host {
		return true
	}
	if old.Type != new.Type {
		return true
	}
	if old.Subnet != new.Subnet {
		return true
	}
	return false
}

func getDNS(dc *config.DNS) dns.DNS {
	_, subnet, err := net.ParseCIDR(dc.Subnet)
	if err != nil {
		if net.ParseIP(dc.Subnet).To4() != nil {
			_, subnet, _ = net.ParseCIDR(dc.Subnet + "/32")
		}

		if net.ParseIP(dc.Subnet).To16() != nil {
			_, subnet, _ = net.ParseCIDR(dc.Subnet + "/128")
		}
	}

	switch dc.Type {
	case config.DNS_doh:
		return dns.NewDoH(dc.Host, subnet, nil)
	case config.DNS_dot:
		return dns.NewDoT(dc.Host, subnet, nil)
	case config.DNS_tcp:
		fallthrough
	case config.DNS_udp:
		fallthrough
	default:
		return dns.NewDNS(dc.Host, subnet, nil)
	}
}

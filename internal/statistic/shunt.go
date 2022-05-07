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

	"github.com/Asutorufa/yuhaiin/pkg/net/mapper"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/proto"
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
}

func newShunt(resolver *remoteResolver) *Shunt {
	mapr := mapper.NewMapper[*MODE](resolver.LookupIP)

	return &Shunt{
		mapper: mapr,
		config: &protoconfig.Bypass{Enabled: true, BypassFile: ""},
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

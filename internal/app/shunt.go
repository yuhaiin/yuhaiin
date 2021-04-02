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

	"github.com/Asutorufa/yuhaiin/pkg/net/mapper"
)

const (
	others = 0
	block  = 1
	direct = 2
	proxy  = 3

	ip     = 0
	domain = 1
)

//go:embed yuhaiin.conf
var bypassData []byte

var modeMapping = map[int]string{
	others: "others(proxy)",
	direct: "direct",
	proxy:  "proxy",
	block:  "block",
}

var mode = map[string]int{
	"direct": direct,
	"proxy":  proxy,
	"block":  block,
}

type Shunt struct {
	file   string
	mapper *mapper.Mapper

	fileLock sync.RWMutex
}

//NewShunt file: bypass file; lookup: domain resolver, can be nil
func NewShunt(file string, lookup func(string) ([]net.IP, error)) (*Shunt, error) {
	s := &Shunt{
		file:   file,
		mapper: mapper.NewMapper(lookup),
	}
	err := s.RefreshMapping()
	if err != nil {
		return nil, fmt.Errorf("refresh mapping failed: %v", err)
	}
	return s, nil
}

func (s *Shunt) RefreshMapping() error {
	s.fileLock.RLock()
	defer s.fileLock.RUnlock()
	log.Println(s.file)
	_, err := os.Stat(s.file)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(path.Dir(s.file), os.ModePerm)
		if err != nil {
			return fmt.Errorf("make dir all failed: %v", err)
		}
		err = ioutil.WriteFile(s.file, bypassData, os.ModePerm)
		if err != nil {
			return fmt.Errorf("write bypass file failed: %v", err)
		}
	}

	f, err := os.Open(s.file)
	if err != nil {
		return fmt.Errorf("open bypass file failed: %v", err)
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
		mode := mode[strings.ToLower(*(*string)(unsafe.Pointer(&result[2])))]
		if mode == others {
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

func getType(b bool) int {
	if b {
		return ip
	}
	return domain
}
func (s *Shunt) Get(domain string) (int, int) {
	mark, markType := s.mapper.Search(domain)
	x, ok := mark.(int)
	if !ok {
		return others, getType(markType)
	}

	if x < others || x > direct {
		x = others
	}

	return x, getType(markType)
}

func (s *Shunt) SetLookup(f func(string) ([]net.IP, error)) {
	s.mapper.SetLookup(f)
}

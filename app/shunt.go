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

	"github.com/Asutorufa/yuhaiin/net/mapper"
)

const (
	others = 0
	direct = 1 << iota
	proxy
	ip
	block
)

//go:embed yuhaiin.conf
var bypassData []byte

var modeMapping = map[int]string{
	direct: "direct",
	proxy:  "proxy",
	block:  "block",
}

var mode = map[string]int{
	"direct":   direct,
	"proxy":    proxy,
	"block":    block,
	"ip":       ip,
	"ipdirect": ip | direct,
}

type Shunt struct {
	file   string
	mapper *mapper.Mapper
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
		mode := mode[strings.ToLower(string(result[2]))]
		if mode == others {
			continue
		}
		_ = s.mapper.Insert(string(result[1]), mode)
	}
	return nil
}

func (s *Shunt) SetFile(f string) error {
	if s.file == f {
		return nil
	}
	s.file = f
	return s.RefreshMapping()
}

func (s *Shunt) Get(domain string) (int, mapper.Category) {
	mark, markType := s.mapper.Search(domain)
	x, ok := mark.(int)
	if !ok {
		return others, markType
	}
	return x, markType
}

func (s *Shunt) SetLookup(f func(string) ([]net.IP, error)) {
	s.mapper.SetLookup(f)
}

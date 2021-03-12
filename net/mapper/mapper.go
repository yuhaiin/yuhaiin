package match

import (
	"net"

	"github.com/Asutorufa/yuhaiin/net/utils"
)

type Mapper struct {
	lookup func(string) ([]net.IP, error)
	cidr   *Cidr
	domain *Domain
	cache  *utils.LRU
}

type Category int

const (
	IP Category = 1 << iota
	DOMAIN
)

type des struct {
	Category Category
	Des      interface{}
}

func (x *Mapper) SetLookup(f func(string) ([]net.IP, error)) {
	x.lookup = f
}

func (x *Mapper) Insert(str string, mark interface{}) error {
	if str == "" {
		return nil
	}
	if _, _, err := net.ParseCIDR(str); err != nil {
		x.domain.Insert(str, mark)
		return nil
	}

	return x.cidr.Insert(str, mark)
}

func (x *Mapper) Search(str string) (mark interface{}, uriType Category) {
	if de := x.cache.Load(str); de != nil {
		return de.(des).Des, de.(des).Category
	}

	var res interface{}
	markType := DOMAIN

	if net.ParseIP(str) != nil {
		_, res = x.cidr.Search(str)
		markType = IP
		goto _end
	}

	_, res = x.domain.Search(str)
	if res != nil {
		goto _end
	}

	if x.lookup == nil {
		goto _end
	}

	if dns, _ := x.lookup(str); len(dns) > 0 {
		_, res = x.cidr.Search(dns[0].String())
	}

_end:
	x.cache.Add(str, des{Des: res, Category: markType})
	return res, markType
}

func (x *Mapper) Clear() {
	x.cidr = NewCidrMapper()
	x.domain = NewDomainMapper()
	x.cache = utils.NewLru(150, 0)
}

func NewMapper(lookup func(string) ([]net.IP, error)) (matcher *Mapper) {
	return &Mapper{
		cidr:   NewCidrMapper(),
		domain: NewDomainMapper(),
		cache:  utils.NewLru(150, 0),
		lookup: lookup,
	}
}

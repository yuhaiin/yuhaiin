package mapper

import (
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

type Mapper struct {
	lookup func(string) ([]net.IP, error)
	cidr   *Cidr
	domain *Domain
	cache  *utils.LRU
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

func (x *Mapper) Search(str string) (mark interface{}, isIP bool) {
	if de := x.cache.Load(str); de != nil {
		if d, ok := de.([2]interface{}); ok {
			return d[0], d[1] == 1
		}
	}

	var res interface{}
	markType := 0

	if net.ParseIP(str) != nil {
		_, res = x.cidr.Search(str)
		markType = 1
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
	x.cache.Add(str, [2]interface{}{res, markType})
	return res, markType == 1
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

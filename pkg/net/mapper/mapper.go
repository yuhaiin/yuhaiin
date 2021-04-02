package mapper

import (
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

type Mapper struct {
	lookup func(string) ([]net.IP, error)
	cidr   *Cidr
	domain *Domain
	cache  *utils.LRU

	lookupLock sync.RWMutex
}

func (x *Mapper) SetLookup(f func(string) ([]net.IP, error)) {
	x.lookupLock.Lock()
	defer x.lookupLock.Unlock()
	x.lookup = f
}

func (x *Mapper) Insert(str string, mark interface{}) {
	if str == "" {
		return
	}

	_, ipNet, err := net.ParseCIDR(str)
	if err != nil {
		x.domain.Insert(str, mark)
	} else {
		x.cidr.InsertCIDR(ipNet, mark)
	}
}

func (x *Mapper) Search(str string) (mark interface{}, isIP bool) {
	if de, _ := x.cache.Load(str); de != nil {
		d := de.([2]interface{})
		return d[0], d[1] == true
	}

	if ip := net.ParseIP(str); ip != nil {
		mark, _ = x.cidr.SearchIP(ip)
		isIP = true
		goto _end
	}

	mark, _ = x.domain.Search(str)
	if mark != nil {
		goto _end
	}

	x.lookupLock.RLock()
	defer x.lookupLock.RUnlock()
	if x.lookup == nil {
		goto _end
	}
	if dns, err := x.lookup(str); err == nil {
		mark, _ = x.cidr.SearchIP(dns[0])
	}

_end:
	x.cache.Add(str, [2]interface{}{mark, isIP})
	return mark, isIP
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

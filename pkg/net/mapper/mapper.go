package mapper

import (
	"net"
	"sync"
)

type Mapper[T any] struct {
	lookup func(string) ([]net.IP, error)
	cidr   *Cidr[T]
	domain *domain[T]

	lookupLock sync.RWMutex
}

func (x *Mapper[T]) SetLookup(f func(string) ([]net.IP, error)) {
	x.lookupLock.Lock()
	defer x.lookupLock.Unlock()
	x.lookup = f
}

func (x *Mapper[T]) Insert(str string, mark T) {
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

func (x *Mapper[T]) Search(str string) (mark T, ok bool) {
	if ip := net.ParseIP(str); ip != nil {
		mark, ok = x.cidr.SearchIP(ip)
		goto _end
	}

	mark, ok = x.domain.Search(str)
	if ok {
		goto _end
	}

	x.lookupLock.RLock()
	defer x.lookupLock.RUnlock()
	if x.lookup == nil {
		goto _end
	}
	if dns, err := x.lookup(str); err == nil {
		mark, ok = x.cidr.SearchIP(dns[0])
	}

_end:
	return
}

func (x *Mapper[T]) Clear() {
	x.cidr = NewCidrMapper[T]()
	x.domain = NewDomainMapper[T]()
}

func NewMapper[T any](lookup func(string) ([]net.IP, error)) (matcher *Mapper[T]) {
	return &Mapper[T]{
		cidr:   NewCidrMapper[T](),
		domain: NewDomainMapper[T](),
		lookup: lookup,
	}
}

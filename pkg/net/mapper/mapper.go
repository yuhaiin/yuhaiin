package mapper

import (
	"fmt"
	"net"
	"sync/atomic"
)

type Mapper[T any] struct {
	preMap []Search[T]
	lookup *value[func(string) ([]net.IP, error)]
	cidr   *Cidr[T]
	domain *domain[T]
}

func (x *Mapper[T]) SetLookup(f func(string) ([]net.IP, error)) {
	x.lookup.Store(f)
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

func (x *Mapper[T]) lookupIP(s string) ([]net.IP, error) {
	lookup := x.lookup.Load()
	if lookup == nil {
		return nil, fmt.Errorf("no lookup function")
	}

	return lookup(s)
}

func (x *Mapper[T]) Search(str string) (mark T, ok bool) {
	for _, f := range x.preMap {
		mark, ok = f.Search(str)
		if ok {
			return
		}
	}

	if ip := net.ParseIP(str); ip != nil {
		return x.cidr.SearchIP(ip)
	}

	if mark, ok = x.domain.Search(str); ok {
		return
	}

	if dns, err := x.lookupIP(str); err == nil {
		mark, ok = x.cidr.SearchIP(dns[0])
	}

	return
}

type Search[T any] interface {
	Search(string) (T, bool)
}

func (x *Mapper[T]) WrapPrefixSearch(f Search[T]) {
	x.preMap = append(x.preMap, f)
}

func (x *Mapper[T]) Clear() {
	x.cidr = NewCidrMapper[T]()
	x.domain = NewDomainMapper[T]()
}

func NewMapper[T any](lookup func(string) ([]net.IP, error)) (matcher *Mapper[T]) {
	return &Mapper[T]{
		cidr:   NewCidrMapper[T](),
		domain: NewDomainMapper[T](),
		lookup: newValue(lookup),
	}
}

type value[T any] struct {
	v atomic.Value
}

func newValue[T any](t T) *value[T] {
	a := &value[T]{v: atomic.Value{}}
	a.Store(t)

	return a
}

func (v *value[T]) Store(t T) {
	v.v.Store(t)
}

func (v *value[T]) Load() (t T) {
	if r := v.v.Load(); r != nil {
		t = r.(T)
	}
	return
}

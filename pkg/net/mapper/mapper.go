package mapper

import (
	"math/rand"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/mapper"
)

type combine[T any] struct {
	cidr   *Cidr[T]
	domain *domain[T]

	dns dns.DNS
}

func (x *combine[T]) Insert(str string, mark T) {
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

func (x *combine[T]) Search(str string) (mark T, ok bool) {
	if ip := net.ParseIP(str); ip != nil {
		return x.cidr.SearchIP(ip)
	}

	if mark, ok = x.domain.Search(str); ok {
		return
	}

	if x.dns == nil {
		return
	}

	if dns, err := x.dns.LookupIP(str); err == nil {
		mark, ok = x.cidr.SearchIP(dns[rand.Intn(len(dns))])
	}

	return
}

func (x *combine[T]) Clear() error {
	x.cidr = NewCidrMapper[T]()
	x.domain = NewDomainMapper[T]()

	return nil
}

func NewMapper[T any](dns dns.DNS) mapper.Mapper[string, T] {
	return &combine[T]{
		cidr:   NewCidrMapper[T](),
		domain: NewDomainMapper[T](),
		dns:    dns,
	}
}

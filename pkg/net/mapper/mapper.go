package mapper

import (
	"math/rand"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/mapper"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	yerr "github.com/Asutorufa/yuhaiin/pkg/utils/error"
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

func (x *combine[T]) Search(str proxy.Address) (mark T, ok bool) {
	if str.Type() == proxy.IP {
		return x.cidr.SearchIP(yerr.Must(str.IP()))
	}

	if mark, ok = x.domain.Search(str); ok {
		return
	}

	if x.dns == nil {
		return
	}

	if dns, err := x.dns.LookupIP(str.Hostname()); err == nil {
		mark, ok = x.cidr.SearchIP(dns.IPs()[rand.Intn(len(dns.IPs()))])
	}

	return
}

func (x *combine[T]) Domain() mapper.Mapper[string, proxy.Address, T] { return x.domain }

func (x *combine[T]) Clear() error {
	x.cidr = NewCidrMapper[T]()
	x.domain = NewDomainMapper[T]()

	return nil
}

func NewMapper[T any](dns dns.DNS) mapper.Mapper[string, proxy.Address, T] {
	return &combine[T]{cidr: NewCidrMapper[T](), domain: NewDomainMapper[T](), dns: dns}
}

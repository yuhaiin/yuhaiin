package mapper

import (
	"math/rand"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/mapper"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
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

func (x *combine[T]) Search(addr proxy.Address) (mark T, ok bool) {
	if addr.Type() == proxy.IP {
		return x.cidr.SearchIP(yerror.Must(addr.IP()))
	}

	if mark, ok = x.domain.Search(addr); ok {
		return
	}

	if x.dns == nil {
		return
	}

	if ips, err := x.dns.LookupIP(addr.Hostname()); err == nil {
		mark, ok = x.cidr.SearchIP(ips[rand.Intn(len(ips))])
	} else {
		log.Warningf("dns lookup %v failed: %v, skip match ip", addr, err)
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

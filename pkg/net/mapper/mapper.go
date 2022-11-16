package mapper

import (
	"errors"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/mapper"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/mapper/cidr"
	"github.com/Asutorufa/yuhaiin/pkg/net/mapper/domain"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

type combine[T any] struct {
	cidr   *cidr.Cidr[T]
	domain *domain.Domain[T]
}

func (x *combine[T]) Insert(str string, mark T) {
	if str == "" {
		return
	}

	_, ipNet, err := net.ParseCIDR(str)
	if err == nil {
		x.cidr.InsertCIDR(ipNet, mark)
		return
	}

	if ip := net.ParseIP(str); ip != nil {
		mask := 128
		if ip.To4() != nil {
			mask = 32
		}
		x.cidr.InsertIP(ip, mask, mark)
		return
	}

	x.domain.Insert(str, mark)

}

func (x *combine[T]) Search(addr proxy.Address) (mark T, ok bool) {
	if addr.Type() == proxy.IP {
		return x.cidr.SearchIP(yerror.Must(addr.IP()))
	}

	if mark, ok = x.domain.Search(addr); ok {
		return
	}

	if ips, err := addr.IP(); err == nil {
		mark, ok = x.cidr.SearchIP(ips)
	} else {
		if !errors.Is(err, mapper.ErrSkipResolveDomain) {
			log.Warningf("dns lookup %v failed: %v, skip match ip", addr, err)
		}
	}

	return
}

func (x *combine[T]) Domain() mapper.Mapper[string, proxy.Address, T] { return x.domain }

func (x *combine[T]) Clear() error {
	x.cidr = cidr.NewCidrMapper[T]()
	x.domain = domain.NewDomainMapper[T]()
	return nil
}

func NewMapper[T any]() mapper.Mapper[string, proxy.Address, T] {
	return &combine[T]{cidr: cidr.NewCidrMapper[T](), domain: domain.NewDomainMapper[T]()}
}

package mapper

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/mapper/cidr"
	"github.com/Asutorufa/yuhaiin/pkg/net/mapper/domain"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

type Combine[T any] struct {
	cidr   *cidr.Cidr[T]
	domain *domain.Domain[T]
}

func (x *Combine[T]) Insert(str string, mark T) {
	if str == "" {
		return
	}

	ipNet, err := netip.ParsePrefix(str)
	if err == nil {
		x.cidr.InsertCIDR(ipNet, mark)
		return
	}

	if ip, err := netip.ParseAddr(str); err == nil {
		mask := 128
		if ip.Is4() {
			mask = 32
		}
		x.cidr.InsertIP(ip, mask, mark)
		return
	}

	x.domain.Insert(str, mark)

}

var ErrSkipResolve = errors.New("skip resolve domain")

var SkipResolve = proxy.ErrorResolver(func(domain string) error { return ErrSkipResolve })

func (x *Combine[T]) Search(ctx context.Context, addr proxy.Address) (mark T, ok bool) {
	if addr.Type() == proxy.IP {
		return x.cidr.SearchIP(yerror.Must(addr.IP(ctx)))
	}

	if mark, ok = x.domain.Search(addr); ok {
		return
	}

	if ips, err := addr.IP(ctx); err == nil {
		mark, ok = x.cidr.SearchIP(ips)
	} else if !errors.Is(err, ErrSkipResolve) {
		log.Warn("dns lookup failed, skip match ip", slog.Any("addr", addr), slog.Any("err", err))
	}

	return
}

func (x *Combine[T]) SearchWithDefault(ctx context.Context, addr proxy.Address, defaultT T) T {
	t, ok := x.Search(ctx, addr)
	if ok {
		return t
	}

	return defaultT
}

func (x *Combine[T]) Clear() error {
	x.cidr = cidr.NewCidrMapper[T]()
	x.domain = domain.NewDomainMapper[T]()
	return nil
}

func NewMapper[T any]() *Combine[T] {
	return &Combine[T]{cidr: cidr.NewCidrMapper[T](), domain: domain.NewDomainMapper[T]()}
}

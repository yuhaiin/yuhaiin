package yuhaiin

import (
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

type CIDR struct {
	IP   string
	Mask int32
}

func ParseCIDR(s string) (*CIDR, error) {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}

	mask, _ := ipNet.Mask.Size()
	ip := ipNet.IP.String()
	return &CIDR{IP: ip, Mask: int32(mask)}, nil
}

type AddRoute interface {
	Add(*CIDR)
}

func FakeDnsCidr(f func(string)) {
	err := newResolverDB().View(func(s *config.Setting) error {
		d := s.GetDns()

		f(d.GetFakednsIpRange())
		f(d.GetFakednsIpv6Range())

		return nil
	})
	if err != nil {
		log.Error("view resolver db failed", "err", err)
	}
}

func IsIPv6() bool {
	var ipv6 bool
	err := newChoreDB().View(func(s *config.Setting) error {
		ipv6 = s.GetIpv6()
		return nil
	})
	if err != nil {
		log.Error("view chore db failed", "err", err)
	}

	return ipv6
}

func AddFakeDnsCidr(process AddRoute) {
	FakeDnsCidr(func(s string) {
		cidr, err := ParseCIDR(s)
		if err != nil {
			log.Error("parse cidr failed", "cidr", s, "err", err)
			return
		}

		process.Add(cidr)
	})
}

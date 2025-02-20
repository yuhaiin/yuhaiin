package yuhaiin

import (
	"log/slog"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
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

var v4DefaultMask = net.CIDRMask(32, 32)
var v6DefaultMask = net.CIDRMask(128, 128)

type AddRoute interface {
	Add(*CIDR)
}

func FakeDnsCidr(f func(string)) {
	err := newResolverDB().View(func(s *pc.Setting) error {
		d := s.GetDns()

		f(d.GetFakednsIpRange())
		f(d.GetFakednsIpv6Range())

		return nil
	})
	if err != nil {
		log.Error("view resolver db failed", slog.Any("err", err))
	}
}

func IsIPv6() bool {
	var ipv6 bool
	err := newChoreDB().View(func(s *pc.Setting) error {
		ipv6 = s.GetIpv6()
		return nil
	})
	if err != nil {
		log.Error("view chore db failed", slog.Any("err", err))
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

func AddRulesCidrv2(process AddRoute) {
	bd := &bypass.Config{}
	_ = newBypassDB().Batch(func(s *pc.Setting) error {
		bd = s.GetBypass()
		return nil
	})

	for _, v := range bd.GetCustomRuleV3() {

		if v.GetMode() == bypass.Mode_direct && v.GetTag() == "" {
			continue
		}

		for _, hostname := range v.GetHostname() {
			_, cidr, err := net.ParseCIDR(hostname)
			if err != nil {
				ip := net.ParseIP(hostname)
				if ip == nil {
					continue
				}

				var mask []byte
				if ip.To4() != nil {
					mask = v4DefaultMask
				} else {
					mask = v6DefaultMask
				}

				cidr = &net.IPNet{
					IP:   ip,
					Mask: mask,
				}
			}

			mask, _ := cidr.Mask.Size()
			ip := cidr.IP.String()

			log.Info("try add route", "addr", &CIDR{
				IP:   ip,
				Mask: int32(mask),
			}, "tag", v.GetTag(), "mode", v.GetMode(), "hostname", hostname)

			process.Add(&CIDR{
				IP:   ip,
				Mask: int32(mask),
			})
		}
	}
}

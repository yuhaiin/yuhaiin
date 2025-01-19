package yuhaiin

import (
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

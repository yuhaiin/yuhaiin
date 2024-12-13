package yuhaiin

import (
	"bufio"
	"bytes"
	"net"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/log"
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

func AddRulesCidr(process AddRoute) {
	s := GetStore("Default")
	r := bufio.NewScanner(strings.NewReader(s.GetString(RuleProxy) + "\n" + s.GetString(RuleBlock)))
	for r.Scan() {
		line := r.Bytes()

		z := bytes.FieldsFunc(line, func(r rune) bool { return r == ',' })
		if len(z) == 0 {
			continue
		}

		_, cidr, err := net.ParseCIDR(string(z[0]))
		if err != nil {
			ip := net.ParseIP(string(z[0]))
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
		})

		process.Add(&CIDR{
			IP:   ip,
			Mask: int32(mask),
		})
	}
}

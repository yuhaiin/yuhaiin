package yuhaiin

import "net"

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

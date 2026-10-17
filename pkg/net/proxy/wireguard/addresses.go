package wireguard

import "net/netip"

func ParseEndpoints(addresses []string) ([]netip.Prefix, error) {
	endpoints := make([]netip.Prefix, 0, len(addresses))
	for _, str := range addresses {
		prefix, err := netip.ParsePrefix(str)
		if err != nil {
			addr, err := netip.ParseAddr(str)
			if err != nil {
				return nil, err
			}

			if addr.Is4() {
				prefix = netip.PrefixFrom(addr, 32)
			} else {
				prefix = netip.PrefixFrom(addr, 128)
			}
		}

		endpoints = append(endpoints, prefix)
	}

	return endpoints, nil
}

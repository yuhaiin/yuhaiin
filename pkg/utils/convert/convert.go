package convert

import (
	"errors"
	"net"

	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

func ToStringMap(addr proxy.Store) map[string]string {
	maps := addr.Map()

	r := make(map[string]string, len(maps))

	for k, v := range maps {
		kk, ok := ToString(k)
		if !ok {
			continue
		}

		vv, ok := ToString(v)
		if !ok {
			continue
		}

		r[kk] = vv
	}

	return r
}

func ToString(t any) (string, bool) {
	switch z := t.(type) {
	case string:
		return z, true
	case interface{ String() string }:
		return z.String(), true
	default:
		return "", false
	}
}

func ToProxyAddress(netType statistic.Type, t any) (dstAddr proxy.Address, err error) {
	switch z := t.(type) {
	case net.Addr:
		dstAddr, err = proxy.ParseSysAddr(z)
	case string:
		dstAddr, err = proxy.ParseAddress(netType, z)
	case interface{ String() string }:
		dstAddr, err = proxy.ParseAddress(netType, z.String())
	default:
		err = errors.New("unsupported type")
	}
	return
}

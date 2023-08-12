package convert

import (
	"errors"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

func ToStringMap(addr netapi.Store) map[string]string {
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

func ToProxyAddress(netType statistic.Type, t any) (dstAddr netapi.Address, err error) {
	switch z := t.(type) {
	case net.Addr:
		dstAddr, err = netapi.ParseSysAddr(z)
	case string:
		dstAddr, err = netapi.ParseAddress(netType, z)
	case interface{ String() string }:
		dstAddr, err = netapi.ParseAddress(netType, z.String())
	default:
		err = errors.New("unsupported type")
	}
	return
}

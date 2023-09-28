//go:build (linux || darwin || windows) && !lite
// +build linux darwin windows
// +build !lite

package main

import (
	"context"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

func init() {
	processDumper = processDumperImpl{}
}

type processDumperImpl struct{}

func (processDumperImpl) ProcessName(network string, src, dst netapi.Address) (string, error) {
	if src.Type() != netapi.IP || dst.Type() != netapi.IP {
		return "", fmt.Errorf("source or destination address is not ip")
	}

	ip := yerror.Ignore(src.IP(context.TODO()))
	to := yerror.Ignore(dst.IP(context.TODO()))

	if to.IsUnspecified() {
		if ip.To4() != nil {
			to = net.IPv4(127, 0, 0, 1)
		} else {
			to = net.IPv6loopback
		}
	}

	return netlink.FindProcessName(network, ip, src.Port().Port(),
		to, dst.Port().Port())
}

//go:build !openwrt
// +build !openwrt

package main

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
	"google.golang.org/grpc"
)

func init() {
	processDumper = processDumperImpl{}
	newGrpcServer = func() *grpc.Server { return grpc.NewServer() }
}

type processDumperImpl struct{}

func (processDumperImpl) ProcessName(network string, src, _ proxy.Address) (string, error) {
	if src.Type() != proxy.IP {
		return "", fmt.Errorf("source address is not ip")
	}
	return netlink.FindProcessName(network, yerror.Ignore(src.IP()), int(src.Port().Port()))
}

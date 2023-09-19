//go:build (linux || darwin || windows) && !lite
// +build linux darwin windows
// +build !lite

package main

import (
	"context"
	"fmt"

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

	return netlink.FindProcessName(network,
		yerror.Ignore(src.IP(context.TODO())), src.Port().Port(),
		yerror.Ignore(dst.IP(context.TODO())), dst.Port().Port())
}

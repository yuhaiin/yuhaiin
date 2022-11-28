package main

import (
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
)

func init() {
	processDumper = processDumperImpl{}
}

type processDumperImpl struct{}

func (processDumperImpl) ProcessName(network string, srcIp string, srcPort int32, _ string, _ int32) (string, error) {
	ip := net.ParseIP(srcIp)
	if ip == nil {
		return "", fmt.Errorf("source address is not ip")
	}
	return netlink.FindProcessName(network, ip, int(srcPort))
}

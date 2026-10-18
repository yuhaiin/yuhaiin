package hysteria2

import (
	"errors"
	"net"
	"strings"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func parseServerAddress(value string) (netapi.Address, portRanges, error) {
	host, ports, err := net.SplitHostPort(value)
	if err != nil || !strings.ContainsAny(ports, ",-") {
		addr, err := netapi.ParseAddress("udp", value)
		return addr, nil, err
	}
	union, err := parseHopPorts(ports)
	if err != nil {
		return nil, nil, err
	}
	addr, err := netapi.ParseAddressPort("udp", host, union[0].Start)
	return addr, union, err
}

func hopIntervalConfig(config contractnode.Hysteria2) (hopInterval, error) {
	fixed, min, max := config.HopIntervalSeconds, config.MinHopIntervalSeconds, config.MaxHopIntervalSeconds
	if fixed != 0 && (min != 0 || max != 0) {
		return hopInterval{}, errors.New("hysteria2 fixed and random hopping intervals are mutually exclusive")
	}
	if min == 0 && max == 0 {
		if fixed == 0 {
			fixed = 30
		}
		min, max = fixed, fixed
	}
	if min < 5 || max < min {
		return hopInterval{}, errors.New("hysteria2 hopping intervals require 5 <= minimum <= maximum seconds")
	}
	return hopInterval{Min: time.Duration(min) * time.Second, Max: time.Duration(max) * time.Second}, nil
}

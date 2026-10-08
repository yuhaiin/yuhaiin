package hysteria2

import (
	"errors"
	"net"
	"strings"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/apernet/hysteria/extras/v2/transport/udphop"
	hyutils "github.com/apernet/hysteria/extras/v2/utils"
)

func parseHopPorts(value string) (hyutils.PortUnion, error) {
	ports := hyutils.ParsePortUnion(value)
	if len(ports) == 0 || ports[0].Start == 0 {
		return nil, errors.New("hysteria2 hopping ports must be a list or range of ports between 1 and 65535")
	}
	return ports, nil
}

func parseServerAddress(value string) (netapi.Address, hyutils.PortUnion, error) {
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

func hopIntervalConfig(config contractnode.Hysteria2) (udphop.HopIntervalConfig, error) {
	fixed, min, max := config.HopIntervalSeconds, config.MinHopIntervalSeconds, config.MaxHopIntervalSeconds
	if fixed != 0 && (min != 0 || max != 0) {
		return udphop.HopIntervalConfig{}, errors.New("hysteria2 fixed and random hopping intervals are mutually exclusive")
	}
	if min == 0 && max == 0 {
		if fixed == 0 {
			fixed = 30
		}
		min, max = fixed, fixed
	}
	if min < 5 || max < min {
		return udphop.HopIntervalConfig{}, errors.New("hysteria2 hopping intervals require 5 <= minimum <= maximum seconds")
	}
	return udphop.HopIntervalConfig{Min: time.Duration(min) * time.Second, Max: time.Duration(max) * time.Second}, nil
}

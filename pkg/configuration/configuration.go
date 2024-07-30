package configuration

import (
	"net/netip"
	"os"
	"time"
)

var Lite = os.Getenv("YUHAIIN_LITE") == "true"

var (
	LogNaxSize = or(1024*1024, 1024*256)
	LogMaxFile = or(5, 0)

	DNSCache = or[uint](1024, 256)

	ProcessDumper = or(true, false)

	Timeout = time.Second * 20
)

func or[T any](a, b T) T {
	if Lite {
		return b
	}

	return a
}

func GetFakeIPRange(ipRange string, ipv6 bool) netip.Prefix {
	ipf, err := netip.ParsePrefix(ipRange)
	if err == nil {
		return ipf
	}

	if ipv6 {
		return netip.MustParsePrefix("fc00::/64")
	} else {
		return netip.MustParsePrefix("10.2.0.1/24")
	}
}

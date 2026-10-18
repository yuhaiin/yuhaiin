package defaults_test

import (
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/defaults"
)

func TestFakeIPPoolsStayWithinBenchmarkRanges(t *testing.T) {
	check := func(prefix netip.Prefix, reserved string, bits int) {
		t.Helper()
		block := netip.MustParsePrefix(reserved)
		if prefix.Bits() != bits || prefix != prefix.Masked() || !block.Contains(prefix.Addr()) {
			t.Fatalf("FakeIP prefix %v must be an aligned /%d inside %s", prefix, bits, reserved)
		}
	}
	for range 256 {
		check(defaults.FakeipV4UlaGenerate(), "198.18.0.0/15", 16)
		check(defaults.FakeipV6UlaGenerate(), "2001:2::/48", 64)
		// The declared defaults remain in the reserved address spaces.
		check(netip.MustParsePrefix(defaults.DefaultFakeIPv4Range), "198.18.0.0/15", 16)
		check(netip.MustParsePrefix(defaults.DefaultFakeIPv6Range), "2001:2::/48", 64)
	}
}

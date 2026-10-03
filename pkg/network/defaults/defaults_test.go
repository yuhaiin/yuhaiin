package defaults_test

import (
	"net/netip"
	"testing"

	legacyconfig "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
	"github.com/Asutorufa/yuhaiin/pkg/network/defaults"
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
		// Configuration seeding must use the same ranges as the generators.
		dns := legacyconfig.DefaultSetting(t.TempDir()).GetDns()
		check(netip.MustParsePrefix(dns.GetFakednsIpRange()), "198.18.0.0/15", 16)
		check(netip.MustParsePrefix(dns.GetFakednsIpv6Range()), "2001:2::/48", 64)
	}
}

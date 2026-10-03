package defaults

import (
	mrand "math/rand/v2"
	"net/netip"
)

// FakeIP pools use subsets of the non-globally-routable benchmarking ranges
// 198.18.0.0/15 (RFC 2544) and 2001:2::/48 (RFC 5180, erratum 1752).
// The old 10.x/16 and fdxx::/64 defaults are classified as local by Chromium;
// Brave/Chrome could reject public-site requests to these FakeIPs with
// ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS before traffic reached the TUN.
// Chromium currently classifies the benchmarking ranges as public instead:
// https://chromium.googlesource.com/chromium/src/+/lkgr/services/network/public/cpp/ip_address_space_util.cc
const (
	DefaultFakeIPv4Range = "198.18.0.0/16"
	DefaultFakeIPv6Range = "2001:2::/64"
)

// FakeipV4UlaGenerate keeps its historical name but selects a benchmarking /16.
// A /16 provides 65,536 FakeIPs without claiming the whole reserved /15;
// randomizing the subnet offers two choices, but does not guarantee no conflicts.
func FakeipV4UlaGenerate() netip.Prefix {
	ip := [4]byte{198, byte(18 + mrand.IntN(2)), 0, 0}
	return netip.PrefixFrom(netip.AddrFrom4(ip), 16)
}

// FakeipV6UlaGenerate keeps its historical name but selects a benchmarking /64.
// A /64 leaves ample host space and 16 bits to randomize the subnet inside /48,
// reducing the chance of a collision without claiming the whole reserved range.
func FakeipV6UlaGenerate() netip.Prefix {
	ip := [16]byte{
		0x20, 0x01, 0x00, 0x02, 0x00, 0x00,
		byte(mrand.IntN(256)), byte(mrand.IntN(256)),
	}
	return netip.PrefixFrom(netip.AddrFrom16(ip), 64)
}

func TunV6UlaGenerate() netip.Prefix {
	ip := [16]byte{
		253,
		byte(mrand.IntN(256)), byte(mrand.IntN(256)), byte(mrand.IntN(256)), byte(mrand.IntN(256)), byte(mrand.IntN(256)),
		255, 255,
		0, 0, 0, 0, 0, 0, 0, 1,
	}
	return netip.PrefixFrom(netip.AddrFrom16(ip), 64)
}

func TunV4UlaGenerate() netip.Prefix {
	ip := [4]byte{172, byte(mrand.IntN(16) + 16), byte(mrand.IntN(256)), 1}
	return netip.PrefixFrom(netip.AddrFrom4(ip), 24)
}

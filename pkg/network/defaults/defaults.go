package defaults

import (
	mrand "math/rand/v2"
	"net/netip"
)

func FakeipV4UlaGenerate() netip.Prefix {
	ip := [4]byte{10, byte(mrand.IntN(256)), 0, 0}
	return netip.PrefixFrom(netip.AddrFrom4(ip), 16)
}

func FakeipV6UlaGenerate() netip.Prefix {
	ip := [16]byte{
		253,
		byte(mrand.IntN(256)), byte(mrand.IntN(256)), byte(mrand.IntN(256)), byte(mrand.IntN(256)), byte(mrand.IntN(256)),
		255, 255,
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

//go:build !android

package netlink

import (
	"net/netip"
	"testing"
)

func TestFindProcess(t *testing.T) {
	// 172.19.0.1:55168
	// 10.0.0.103:443
	src := netip.MustParseAddrPort("172.19.0.1:40498")
	to := netip.MustParseAddrPort("10.0.0.103:443")
	t.Log(FindProcessName("udp", src, to))
}

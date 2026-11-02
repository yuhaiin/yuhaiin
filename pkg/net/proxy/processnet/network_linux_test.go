//go:build linux && !android

package processnet

import (
	"net/netip"
	"testing"

	"github.com/yuhaiin/sessionnet"
)

func TestCheckFakeIPOverlap(t *testing.T) {
	for _, tc := range []struct {
		name, prefix    string
		ipv6, wantError bool
	}{
		{"default fake IPv4", "198.18.0.0/15", true, false},
		{"default fake IPv6", "2001:2::/48", true, false},
		{"contains link", "172.31.254.0/24", false, true},
		{"gateway only", "172.31.254.1/32", false, true},
		{"guest only", "172.31.254.2/32", false, true},
		{"IPv6 link", "fd42:7d2a:9b31::/64", true, true},
		{"disabled IPv6", "fd42:7d2a:9b31::/64", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckFakeIPOverlap(sessionnet.AddressConfig{}, [2]netip.Prefix{netip.MustParsePrefix(tc.prefix)}, tc.ipv6)
			if (err != nil) != tc.wantError {
				t.Fatalf("got %v, want error %v", err, tc.wantError)
			}
		})
	}
}

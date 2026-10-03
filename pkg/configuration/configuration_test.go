package configuration

import (
	"net/netip"
	"testing"
)

func TestGetFakeIPRange(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input string
		ipv6  bool
		want  string
	}{
		{"empty IPv4", "", false, "198.18.0.0/16"},
		{"invalid IPv4", "invalid", false, "198.18.0.0/16"},
		{"empty IPv6", "", true, "2001:2::/64"},
		{"invalid IPv6", "invalid", true, "2001:2::/64"},
		{"custom IPv4", "10.42.0.0/16", false, "10.42.0.0/16"},
		{"custom IPv6", "fd44:8589:cd09:ffff::/64", true, "fd44:8589:cd09:ffff::/64"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetFakeIPRange(tt.input, tt.ipv6); got != netip.MustParsePrefix(tt.want) {
				t.Fatalf("GetFakeIPRange(%q, %v) = %v, want %s", tt.input, tt.ipv6, got, tt.want)
			}
		})
	}
}

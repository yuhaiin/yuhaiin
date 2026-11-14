package dialer

import "testing"

func TestSkipInterfaceBind(t *testing.T) {
	for _, tc := range []struct {
		address string
		skip    bool
	}{
		// Wildcard listen sockets egress by the routing table and must be bound.
		{"0.0.0.0:0", false},
		{"[::]:41641", false},
		{":0", false},
		{"1.1.1.1:443", false},
		{"[2606:4700::1111]:443", false},
		{"example.com:443", false},
		{"", false},
		{"127.0.0.1:53", true},
		{"[::1]:53", true},
		{"169.254.1.1:80", true},
		{"[fe80::1]:80", true},
		{"224.0.0.251:5353", true},
	} {
		if got := skipInterfaceBind(tc.address); got != tc.skip {
			t.Errorf("skipInterfaceBind(%q) = %v, want %v", tc.address, got, tc.skip)
		}
	}
}

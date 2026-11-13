package netlink

import (
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDarwinExistingRoute(t *testing.T) {
	gateway4 := netip.MustParseAddr("172.19.0.1")
	gateway6 := netip.MustParseAddr("fdfe:dcba:9876::1")
	for _, tt := range []struct {
		name       string
		index      int
		gateway    netip.Addr
		tunGateway netip.Addr
		conflict   bool
	}{
		{"same TUN IPv4", 8, gateway4, gateway4, false},
		{"same TUN IPv6", 8, gateway6, gateway6, false},
		{"same TUN without gateway", 8, netip.Addr{}, gateway4, false},
		{"physical interface IPv4", 4, netip.MustParseAddr("192.168.1.1"), gateway4, true},
		{"other utun IPv6", 12, netip.MustParseAddr("fd7a:115c:a1e0::1"), gateway6, true},
		{"same TUN other gateway", 8, netip.MustParseAddr("172.19.0.2"), gateway4, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			owned, err := darwinExistingRoute(8, tt.tunGateway, tt.index, tt.gateway, unix.EEXIST)
			if owned {
				t.Fatal("an existing route must never be owned (deleted) by the TUN")
			}
			if got := errors.Is(err, ErrRouteConflict); got != tt.conflict {
				t.Fatalf("conflict = %v (%v), want %v", got, err, tt.conflict)
			}
			if tt.conflict && !errors.Is(err, unix.EEXIST) {
				t.Fatal("conflict lost the RTM_ADD error")
			}
		})
	}
}

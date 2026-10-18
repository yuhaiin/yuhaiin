package interfaces

import (
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestDarwinRouteChangesTriggerReconciliation(t *testing.T) {
	// The cached route trie includes non-default routes too. Both additions
	// and removals of non-default routes need to trigger a fresh snapshot.
	msg := &route.RouteMessage{
		Type: unix.RTM_ADD,
		Addrs: []route.Addr{
			unix.RTAX_DST: &route.Inet4Addr{IP: [4]byte{10, 20, 0, 0}},
		},
	}
	if skipMessage(msg) {
		t.Fatal("non-default route changes must not be filtered")
	}
	msg.Type = unix.RTM_DELETE
	if skipMessage(msg) {
		t.Fatal("deleted non-default routes must not be filtered")
	}
}

func TestDarwinMulticastEventIgnored(t *testing.T) {
	if !skipMessage(&route.InterfaceMulticastAddrMessage{}) {
		t.Fatal("multicast address updates should not trigger a refresh")
	}
}

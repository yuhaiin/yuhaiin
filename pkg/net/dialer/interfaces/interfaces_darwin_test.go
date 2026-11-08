package interfaces

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestDarwinMonitorStopUnblocksIdleRead(t *testing.T) {
	// Use a quiet socket so unrelated changes to the host's routing table do
	// not wake the monitor before cancellation.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	messages := make(chan []route.Message, 1)
	m := &monitor{ctx: ctx, cancel: cancel, done: make(chan struct{}), onMsg: func(msgs []route.Message) { messages <- msgs }}
	result := make(chan error, 1)
	go func() {
		defer close(m.done)
		result <- m.readRouteSocket(fds[0])
	}()
	msg := &route.RouteMessage{Version: unix.RTM_VERSION, Type: unix.RTM_ADD, Index: 1,
		Addrs: []route.Addr{unix.RTAX_DST: &route.Inet4Addr{IP: [4]byte{192, 0, 2, 5}}}}
	data, err := msg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(fds[1], data); err != nil {
		t.Fatal(err)
	}
	select {
	case msgs := <-messages:
		if len(msgs) != 1 {
			t.Fatalf("received %d route messages, want 1", len(msgs))
		}
		rm, ok := msgs[0].(*route.RouteMessage)
		if !ok || rm.Type != msg.Type || rm.Index != msg.Index {
			t.Fatalf("unexpected route message: %+v", msgs[0])
		}
	case <-time.After(time.Second):
		t.Fatal("route message was not delivered")
	}
	// Let the read reach the idle wait before calling Stop.
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("stopping an idle monitor took %s", elapsed)
	} else {
		t.Logf("stopped idle monitor in %s", elapsed)
	}
	if err := <-result; err != nil {
		t.Fatalf("cancellation returned an error: %v", err)
	}
}

func TestDarwinRouteSocketCancellation(t *testing.T) {
	for _, immediate := range []bool{false, true} {
		for range 5 {
			ctx, cancel := context.WithCancel(t.Context())
			m := &monitor{ctx: ctx, onMsg: func([]route.Message) {}}
			result := make(chan error, 1)
			go func() { result <- m.start() }()
			if !immediate {
				// Exercise runtime-poller registration on a real AF_ROUTE socket.
				select {
				case err := <-result:
					cancel()
					t.Fatalf("route monitor exited before cancellation: %v", err)
				case <-time.After(50 * time.Millisecond):
				}
			}
			cancel()
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("route socket did not stop after cancellation")
			}
		}
	}
}

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

func TestSameRouteInterfaceNames(t *testing.T) {
	ifaces := map[int]Interface{
		1: {Interface: &net.Interface{Index: 1, Name: "en0"}},
		2: {Interface: &net.Interface{Index: 2, Name: "utun0"}},
	}
	names := map[int]string{1: "en0", 2: "utun0"}
	if !sameRouteInterfaceNames(names, ifaces) {
		t.Fatal("same interface names must reuse parsed route snapshot")
	}
	ifaces[2] = Interface{Interface: &net.Interface{Index: 2, Name: "utun1"}}
	if sameRouteInterfaceNames(names, ifaces) {
		t.Fatal("renamed interface must invalidate parsed route snapshot")
	}
}

func TestDarwinRouteChurnIgnored(t *testing.T) {
	for _, msg := range []*route.RouteMessage{
		{Type: unix.RTM_GET},
		{Type: unix.RTM_MISS},
		{Type: unix.RTM_ADD, Flags: unix.RTF_LLINFO},
		{Type: unix.RTM_DELETE, Flags: unix.RTF_WASCLONED},
		{Type: unix.RTM_ADD, Flags: unix.RTF_IFSCOPE},
	} {
		if !skipMessage(msg) {
			t.Errorf("route message type=%d flags=%#x should not trigger a refresh", msg.Type, msg.Flags)
		}
	}
	if skipMessage(&route.RouteMessage{Type: unix.RTM_CHANGE, Flags: unix.RTF_GATEWAY | unix.RTF_STATIC}) {
		t.Error("changed static routes must trigger a refresh")
	}
}

func TestDarwinDefaultRouteIndexFromMessages(t *testing.T) {
	def := func(index int, v6 bool, flags int) route.Message {
		addrs := make([]route.Addr, unix.RTAX_NETMASK+1)
		if v6 {
			addrs[unix.RTAX_DST], addrs[unix.RTAX_NETMASK] = &route.Inet6Addr{}, &route.Inet6Addr{}
		} else {
			addrs[unix.RTAX_DST], addrs[unix.RTAX_NETMASK] = &route.Inet4Addr{}, &route.Inet4Addr{}
		}
		return &route.RouteMessage{Index: index, Flags: unix.RTF_GATEWAY | flags, Addrs: addrs}
	}
	if got, err := defaultRouteIndexFromMessages([]route.Message{def(3, true, 0), def(4, false, unix.RTF_IFSCOPE), def(5, false, 0)}); err != nil || got != 5 {
		t.Fatalf("default = %d, %v; want IPv4 index 5", got, err)
	}
	if got, err := defaultRouteIndexFromMessages([]route.Message{def(3, true, 0)}); err != nil || got != 3 {
		t.Fatalf("default = %d, %v; want IPv6 fallback 3", got, err)
	}
	if _, err := defaultRouteIndexFromMessages(nil); err != ErrNoGatewayIndexFound {
		t.Fatalf("missing default error = %v", err)
	}
}

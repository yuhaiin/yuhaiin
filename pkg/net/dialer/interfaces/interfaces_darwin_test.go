package interfaces

import (
	"context"
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

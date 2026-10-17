package tailscale

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
)

func TestTailnetTunCloseBeforeAssignment(t *testing.T) {
	n := newTailnetTun()
	done := make(chan error, 2)
	go func() { _, err := n.Read(make([]byte, 4096), make([]tun.ReadPacket, 1)); done <- err }()
	go func() { _, err := n.Write([][]byte{{0x45}}, 0); done <- err }()
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		select {
		case err := <-done:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("unassigned TUN did not close")
		}
	}
	if err := n.configure(netip.MustParseAddr("100.64.0.1"), netip.Addr{}); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
func TestTailnetTunAssignment(t *testing.T) {
	n := newTailnetTun()
	defer n.Close()
	v4, v6 := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a:115c:a1e0::1")
	if err := n.configure(v4, v6); err != nil {
		t.Fatal(err)
	}
	original, err := n.await()
	if err != nil {
		t.Fatal(err)
	}
	if err := n.configure(v4, v6); err != nil {
		t.Fatal(err)
	}
	again, err := n.await()
	if err != nil || again != original {
		t.Fatal("repeated Up replaced active stack")
	}
	if err := n.configure(netip.MustParseAddr("100.64.0.2"), v6); err == nil {
		t.Fatal("changed identity silently retained stale source IP")
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := n.await(); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

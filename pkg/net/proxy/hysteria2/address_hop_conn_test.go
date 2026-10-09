package hysteria2

import (
	"context"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	node "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/apernet/hysteria/extras/v2/transport/udphop"
)

func testAddressHopAddr(t *testing.T, first, second string) *addressHopAddr {
	t.Helper()
	config := node.Hysteria2{Host: first, HopAddresses: []string{second}}
	addr, ports, err := parseServerAddress(first)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := resolveHopAddress(t.Context(), addr)
	if err != nil {
		t.Fatal(err)
	}
	result, err := resolveAddressHops(t.Context(), config, remote, ports)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestAddressHopTargetsMergePortRanges(t *testing.T) {
	addr := testAddressHopAddr(t, "127.0.0.2:443,20000-20002", "127.0.0.2:20001-20003")
	if len(addr.targets) != 1 {
		t.Fatalf("duplicate IP targets: %v", addr.targets)
	}
	ports := addr.targets[0].ports
	if len(ports) != 5 || ports[0] != 443 || ports[1] != 20000 || ports[4] != 20003 {
		t.Fatalf("merged port ranges: %v", ports)
	}
	addr = testAddressHopAddr(t, "127.0.0.2", "[::1]:8443")
	if len(addr.targets) != 2 || addr.targets[0].ports[0] != 443 || addr.targets[1].ports[0] != 8443 {
		t.Fatalf("default port or address family lost: %+v", addr.targets)
	}
}

func TestAddressHopSocketLifecycle(t *testing.T) {
	listeners := make([]net.PacketConn, 2)
	for i, ip := range []string{"127.0.0.2", "127.0.0.3"} {
		conn, err := net.ListenPacket("udp4", net.JoinHostPort(ip, "0"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		listeners[i] = conn
	}
	addr := testAddressHopAddr(t, listeners[0].LocalAddr().String(), listeners[1].LocalAddr().String())
	setup, cancelSetup := context.WithCancel(t.Context())
	defer cancelSetup()
	tracker := &addressTestDialer{}
	var fail atomic.Bool
	listen := func(ctx context.Context, remote net.Addr) (net.PacketConn, error) {
		if fail.Load() {
			return nil, errors.New("temporary socket failure")
		}
		target, err := netapi.ParseSysAddr(remote)
		if err != nil {
			return nil, err
		}
		return tracker.PacketConn(ctx, target)
	}
	c, err := newAddressHopPacketConn(setup, t.Context(), addr, udphop.HopIntervalConfig{Min: time.Hour, Max: time.Hour}, listen)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	cancelSetup() // Later sockets must use the client lifetime, not setup.

	exchange := func(want string) (net.PacketConn, net.Addr) {
		t.Helper()
		if _, err := c.WriteTo([]byte(want), addr); err != nil {
			t.Fatal(err)
		}
		c.mu.Lock()
		remote := c.current.remote.String()
		c.mu.Unlock()
		for _, listener := range listeners {
			if listener.LocalAddr().String() != remote {
				continue
			}
			_ = listener.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 64)
			n, from, err := listener.ReadFrom(buf)
			if err != nil || string(buf[:n]) != want {
				t.Fatalf("relay received %q: %v", buf[:n], err)
			}
			return listener, from
		}
		t.Fatal("unknown relay target")
		return nil, nil
	}
	oldListener, oldLocal := exchange("before hop")
	c.hop()
	newListener, newLocal := exchange("after hop")
	if oldListener == newListener || oldLocal.String() == newLocal.String() {
		t.Fatal("hop did not change the target IP and local socket")
	}
	// Late packets arriving on the previous socket are still readable, and
	// both relay IPs are presented to QUIC as the same logical peer.
	for _, reply := range []struct {
		listener net.PacketConn
		local    net.Addr
		payload  string
	}{{oldListener, oldLocal, "old reply"}, {newListener, newLocal, "new reply"}} {
		if _, err := reply.listener.WriteTo([]byte(reply.payload), reply.local); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 64)
		n, peer, err := c.ReadFrom(buf)
		if err != nil || peer != addr || string(buf[:n]) != reply.payload {
			t.Fatalf("reply %q, peer %v: %v", buf[:n], peer, err)
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(-time.Second))
	if _, _, err := c.ReadFrom(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read deadline: %v", err)
	}
	_ = c.SetDeadline(time.Time{})
	fail.Store(true)
	c.hop()
	if tracker.opened.Load() != 2 {
		t.Fatal("failed hop replaced the current socket")
	}
	exchange("after failed hop")
	fail.Store(false)
	_ = c.SetWriteDeadline(time.Now().Add(-time.Second))
	c.hop()
	if _, err := c.WriteTo([]byte("expired"), addr); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write deadline lost across hop: %v", err)
	}
	_ = c.SetDeadline(time.Time{})
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if tracker.opened.Load() != 3 || tracker.closed.Load() != 3 {
		t.Fatalf("socket leak: opened %d, closed %d", tracker.opened.Load(), tracker.closed.Load())
	}
	if _, _, err := c.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after close: %v", err)
	}
	if _, err := c.WriteTo([]byte("closed"), addr); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}
}

func TestAddressHopCloseCancelsSocketOpen(t *testing.T) {
	addr := testAddressHopAddr(t, "127.0.0.2:443", "127.0.0.3:443")
	var calls atomic.Int32
	opening := make(chan struct{})
	listen := func(ctx context.Context, _ net.Addr) (net.PacketConn, error) {
		if calls.Add(1) == 1 {
			return net.ListenPacket("udp4", "127.0.0.1:0")
		}
		close(opening)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	c, err := newAddressHopPacketConn(t.Context(), t.Context(), addr, udphop.HopIntervalConfig{Min: time.Millisecond, Max: time.Millisecond}, listen)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	select {
	case <-opening:
	case <-time.After(time.Second):
		t.Fatal("hop did not open a socket")
	}
	done := make(chan error, 1)
	go func() { done <- c.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not cancel an in-progress hop")
	}
}

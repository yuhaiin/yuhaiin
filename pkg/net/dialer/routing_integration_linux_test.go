//go:build linux && !android

package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
	vnl "github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// These tests build a network inside a fresh network namespace:
//
//	nic1  192.168.10.2/24  fd10::2/64   main default via 192.168.10.1 / fd10::1
//	nic2  192.168.20.2/24  fd20::2/64   connected LAN only
//	yhtun 172.19.0.1/24    fd19::1/64   "our TUN": table 63 holds 0.0.0.0/1,
//	                                    128.0.0.0/1 and ::/1, 8000::/1 via it
//
// Dummy links transmit into nothing but count what they send, so each check
// asserts the interface a packet actually left through, not that a socket
// option was accepted. Run as root with YUHAIIN_TEST_TUN_ROUTES=1.

func routingNamespace(t *testing.T) {
	t.Helper()
	if os.Getenv("YUHAIIN_TEST_TUN_ROUTES") != "1" {
		t.Skip("set YUHAIIN_TEST_TUN_ROUTES=1 as root in a Linux environment with network namespace privileges")
	}
	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	isolated, err := netns.New()
	if err != nil {
		runtime.UnlockOSThread()
		t.Skipf("isolated network namespace unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Set(original)
		_ = isolated.Close()
		_ = original.Close()
		runtime.UnlockOSThread()
	})
	if lo, err := vnl.LinkByName("lo"); err == nil {
		_ = vnl.LinkSetUp(lo)
	}
}

func addDummy(t *testing.T, name string, addrs ...string) vnl.Link {
	t.Helper()
	if err := vnl.LinkAdd(&vnl.Dummy{Name: name}); err != nil {
		t.Fatal(err)
	}
	link, err := vnl.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		addr, err := vnl.ParseAddr(a)
		if err != nil {
			t.Fatal(err)
		}
		// No DAD: the address is usable at once.
		addr.Flags = unix.IFA_F_NODAD
		if err := vnl.AddrAdd(link, addr); err != nil {
			t.Fatal(err)
		}
	}
	if err := vnl.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	return link
}

// txPackets reads the counter over netlink: /sys/class/net shows the mount
// namespace's network, not the one this thread entered.
func txPackets(t *testing.T, name string) uint64 {
	t.Helper()
	link, err := vnl.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	if link.Attrs().Statistics == nil {
		t.Fatalf("%s: no statistics", name)
	}
	return link.Attrs().Statistics.TxPackets
}

type counters map[string]uint64

func snapshot(t *testing.T) counters {
	return counters{"nic1": txPackets(t, "nic1"), "nic2": txPackets(t, "nic2"), "yhtun": txPackets(t, "yhtun")}
}

// sentOnlyOn asserts that since before, packets left through want and through
// no other test interface.
func sentOnlyOn(t *testing.T, what string, before counters, want string) {
	t.Helper()
	// Transmit accounting is synchronous for dummy links, but allow the
	// stack a moment for TCP SYNs sent from another goroutine.
	deadline := time.Now().Add(time.Second)
	for {
		after := snapshot(t)
		ok := after[want] > before[want]
		for name := range after {
			if name != want && after[name] != before[name] {
				t.Fatalf("%s: left through %s (tx %d -> %d), want only %s", what, name, before[name], after[name], want)
			}
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: nothing sent through %s", what, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type routingNet struct {
	nic1, nic2, tun vnl.Link
	routes          *netlink.RouteManager
}

func buildRoutingNet(t *testing.T) *routingNet {
	t.Helper()
	n := &routingNet{
		nic1: addDummy(t, "nic1", "192.168.10.2/24", "fd10::2/64"),
		nic2: addDummy(t, "nic2", "192.168.20.2/24", "fd20::2/64"),
		tun:  addDummy(t, "yhtun", "172.19.0.1/24", "fd19::1/64"),
	}
	for _, gw := range []string{"192.168.10.1", "fd10::1"} {
		r := vnl.Route{LinkIndex: n.nic1.Attrs().Index, Gw: net.ParseIP(gw)}
		if err := vnl.RouteAdd(&r); err != nil {
			t.Fatalf("default via %s: %v", gw, err)
		}
	}
	m, err := netlink.NewRouteManager()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	var desired []netlink.SystemRoute
	for _, p := range []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"} {
		desired = append(desired, netlink.SystemRoute{Prefix: netip.MustParsePrefix(p), Link: n.tun.Attrs().Index})
	}
	if _, err := m.Update(desired); err != nil {
		t.Fatal(err)
	}
	n.routes = m

	oldSkip := SkipInterface
	SkipInterface = func() *set.Set[string] { s := set.NewSet[string](); s.Push("yhtun"); return s }
	t.Cleanup(func() { SkipInterface = oldSkip })
	return n
}

func installMark(t *testing.T) {
	t.Helper()
	if err := InstallMarkProtector(netlink.SocketProtectionMark); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { SetSocketProtector(nil) })
}

func udpSend(t *testing.T, pc net.PacketConn, dst string) error {
	t.Helper()
	_, err := pc.WriteTo([]byte("x"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort(dst)))
	return err
}

// Ordinary applications still follow the System Network rules into the TUN.
func TestRoutingUnmarkedTrafficUsesTun(t *testing.T) {
	routingNamespace(t)
	buildRoutingNet(t)
	for _, dst := range []string{"8.8.8.8:53", "[2001:4860::8888]:53"} {
		pc, err := net.ListenPacket("udp", ":0")
		if err != nil {
			t.Fatal(err)
		}
		before := snapshot(t)
		if err := udpSend(t, pc, dst); err != nil {
			t.Fatal(err)
		}
		sentOnlyOn(t, "unmarked "+dst, before, "yhtun")
		_ = pc.Close()
	}
}

// One protected UDP socket reaches the Internet through nic1, the second
// LAN through nic2 and loopback, per packet, without an interface binding.
func TestRoutingMarkedUDPPerDestination(t *testing.T) {
	routingNamespace(t)
	buildRoutingNet(t)
	installMark(t)

	pc, err := ListenPacket(context.Background(), "udp", "")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	assertNotBound(t, pc.(*UDPConn).UDPConn)

	for _, tc := range []struct{ dst, iface string }{
		{"8.8.8.8:53", "nic1"},
		{"192.168.20.50:53", "nic2"},
		{"[2001:4860::8888]:53", "nic1"},
		{"[fd20::50]:53", "nic2"},
		{"1.1.1.1:443", "nic1"},
	} {
		before := snapshot(t)
		if err := udpSend(t, pc, tc.dst); err != nil {
			t.Fatalf("send %s: %v", tc.dst, err)
		}
		sentOnlyOn(t, "marked "+tc.dst, before, tc.iface)
	}

	// Loopback stays reachable from the same socket.
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	if _, err := pc.WriteTo([]byte("lo"), echo.LocalAddr()); err != nil {
		t.Fatalf("loopback send: %v", err)
	}
	_ = echo.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := echo.ReadFrom(make([]byte, 8)); err != nil {
		t.Fatalf("loopback receive: %v", err)
	}
}

func TestRoutingMarkedTCP(t *testing.T) {
	routingNamespace(t)
	buildRoutingNet(t)
	installMark(t)
	for _, tc := range []struct{ dst, iface string }{
		{"8.8.8.8:443", "nic1"},
		{"192.168.20.50:443", "nic2"},
		{"[2001:4860::8888]:443", "nic1"},
		{"[fd20::50]:443", "nic2"},
	} {
		before := snapshot(t)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		conn, err := DialTCPContext(ctx, netip.MustParseAddrPort(tc.dst))
		cancel()
		if err == nil {
			_ = conn.Close()
		}
		// Nothing answers on a dummy link: the dial times out, but its SYN
		// must have left through the right interface.
		sentOnlyOn(t, "TCP "+tc.dst, before, tc.iface)
	}
}

// Without a usable main route a marked packet fails; it never falls back
// into the TUN table.
func TestRoutingMarkedNoRouteNeverUsesTun(t *testing.T) {
	routingNamespace(t)
	n := buildRoutingNet(t)
	installMark(t)
	for _, gw := range []string{"192.168.10.1", "fd10::1"} {
		r := vnl.Route{LinkIndex: n.nic1.Attrs().Index, Gw: net.ParseIP(gw)}
		if err := vnl.RouteDel(&r); err != nil {
			t.Fatal(err)
		}
	}
	pc, err := ListenPacket(context.Background(), "udp", "")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	before := snapshot(t)
	for _, dst := range []string{"8.8.8.8:53", "[2001:4860::8888]:53"} {
		if err := udpSend(t, pc, dst); !errors.Is(err, unix.ENETUNREACH) {
			t.Fatalf("send %s without a main route: %v, want ENETUNREACH", dst, err)
		}
	}
	if after := snapshot(t); after["yhtun"] != before["yhtun"] {
		t.Fatalf("marked packet entered the TUN: tx %d -> %d", before["yhtun"], after["yhtun"])
	}
}

// Without SO_MARK, sockets fall back to binding the egress interface chosen
// with the TUN excluded.
func TestRoutingMarkFailureFallsBackToBinding(t *testing.T) {
	routingNamespace(t)
	buildRoutingNet(t)
	SetSocketProtector(&SocketProtector{Method: "SO_MARK", Mark: netlink.SocketProtectionMark, Protect: func(int32) error { return unix.EPERM }})
	t.Cleanup(func() { SetSocketProtector(nil) })
	refreshRoutes(t)

	pc, err := ListenPacket(context.Background(), "udp4", "", func(o *Options) {
		o.PacketConnHintAddress = net.UDPAddrFromAddrPort(netip.MustParseAddrPort("8.8.8.8:53"))
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	before := snapshot(t)
	if err := udpSend(t, pc, "8.8.8.8:53"); err != nil {
		t.Fatal(err)
	}
	sentOnlyOn(t, "fallback-bound 8.8.8.8", before, "nic1")
	if r := Protection(); r.Failures == 0 || r.LastError == "" {
		t.Fatalf("protection failure not recorded: %+v", r)
	}
}

// An explicit interface wins over automatic selection, even with the mark.
func TestRoutingExplicitInterface(t *testing.T) {
	routingNamespace(t)
	buildRoutingNet(t)
	installMark(t)
	pc, err := ListenPacket(context.Background(), "udp4", "", func(o *Options) { o.InterfaceName = "nic2" })
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	before := snapshot(t)
	// A destination off nic2's subnet still leaves through nic2 (onlink
	// lookups for a bound socket use that device's routes).
	if err := udpSend(t, pc, "192.168.20.77:53"); err != nil {
		t.Fatal(err)
	}
	sentOnlyOn(t, "explicit nic2", before, "nic2")

	if _, err := ListenPacket(context.Background(), "udp4", "", func(o *Options) { o.InterfaceName = "yhtun" }); err == nil {
		t.Fatal("binding our own TUN explicitly must be refused")
	}
}

func assertNotBound(t *testing.T, c *net.UDPConn) {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var dev string
	var mark int
	var optErr error
	_ = raw.Control(func(fd uintptr) {
		dev, optErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
		if optErr == nil {
			mark, optErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
		}
	})
	if optErr != nil {
		t.Fatal(optErr)
	}
	if dev != "" {
		t.Fatalf("protected socket bound to %q", dev)
	}
	if mark != netlink.SocketProtectionMark {
		t.Fatalf("socket mark = %#x, want %#x", mark, netlink.SocketProtectionMark)
	}
}

func refreshRoutes(t *testing.T) {
	t.Helper()
	if err := interfaces.Refresh("test"); err != nil {
		t.Fatal(err)
	}
}

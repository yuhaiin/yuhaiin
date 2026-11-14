//go:build darwin

package dialer

import (
	"context"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
	"golang.org/x/sys/unix"
)

// TestMacOSEgressTwoInterfaces sends from one relay conn to the Internet and
// to a peer behind a second interface, as with our TUN up, and requires both
// replies. Opt in with a reachable UDP echo on another interface's network:
//
//	YUHAIIN_TEST_MACOS_EGRESS_PEER=10.211.55.6:9999 go test -run TestMacOSEgress ./pkg/net/dialer
//
// The test changes no routes; it only pretends a TUN of ours exists.
func TestMacOSEgressTwoInterfaces(t *testing.T) {
	peerEnv := os.Getenv("YUHAIIN_TEST_MACOS_EGRESS_PEER")
	if peerEnv == "" {
		t.Skip("set YUHAIIN_TEST_MACOS_EGRESS_PEER to a UDP echo reachable through a second interface")
	}
	peer := netip.MustParseAddrPort(peerEnv)
	if err := interfaces.Refresh("test"); err != nil {
		t.Fatal(err)
	}
	// Treat the tunnel that now carries the Internet (a running Yuhaiin
	// TUN or VPN) as ours; without one, pretend a TUN exists.
	ours := "utun-yuhaiin-test"
	if r, ok := interfaces.SelectRoute(netip.MustParseAddr("8.8.8.8"), nil); ok && strings.HasPrefix(r.Interface, "utun") {
		ours = r.Interface
	}
	oldSkip := SkipInterface
	SkipInterface = func() *set.Set[string] { s := set.NewSet[string](); s.Push(ours); return s }
	t.Cleanup(func() { SkipInterface = oldSkip })
	exclude := func(name string) bool { return name == ours }
	peerRoute, ok := interfaces.SelectRoute(peer.Addr(), exclude)
	internet, ok2 := interfaces.SelectRoute(netip.MustParseAddr("8.8.8.8"), exclude)
	if !ok || !ok2 || peerRoute.Interface == internet.Interface {
		t.Skipf("peer and Internet share an interface (%v, %v)", peerRoute, internet)
	}
	t.Logf("our TUN %s; Internet via %s, peer via %s", ours, internet.Interface, peerRoute.Interface)

	pc, err := ListenPacketEgress(context.Background(), "udp")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	conn, ok := pc.(*egressPacketConn)
	if !ok {
		t.Fatalf("relay conn is %T, want per-destination egress", pc)
	}

	// A DNS query for "." NS: any resolver answers, proving the en0 socket
	// really left and came back while bound.
	query := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1}
	if _, err := pc.WriteTo(query, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("8.8.8.8:53"))); err != nil {
		t.Fatalf("send to Internet: %v", err)
	}
	if _, err := pc.WriteTo([]byte("yuhaiin-egress"), net.UDPAddrFromAddrPort(peer)); err != nil {
		t.Fatalf("send to peer: %v", err)
	}
	got := map[string]bool{}
	buf := make([]byte, 2048)
	for len(got) < 2 {
		_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("replies so far %v: %v", got, err)
		}
		got[from.String()] = n > 0
	}
	if !got["8.8.8.8:53"] || !got[peer.String()] {
		t.Fatalf("replies = %v", got)
	}

	ifaces := conn.Interfaces()
	slices.Sort(ifaces)
	want := []string{internet.Interface, peerRoute.Interface}
	slices.Sort(want)
	if !slices.Equal(ifaces, want) {
		t.Fatalf("egress sockets = %v, want %v", ifaces, want)
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	for name, s := range conn.sockets {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if bound := boundInterfaceOf(t, s.conn); bound != iface.Index {
			t.Fatalf("%s socket bound to index %d, want %d", name, bound, iface.Index)
		}
	}
}

func boundInterfaceOf(t *testing.T, pc net.PacketConn) int {
	t.Helper()
	sc, ok := pc.(syscall.Conn)
	if !ok {
		t.Fatalf("%T has no SyscallConn", pc)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var index int
	var optErr error
	_ = raw.Control(func(fd uintptr) {
		// The relay socket is dual-stack AF_INET6.
		index, optErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF)
		if optErr != nil {
			index, optErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF)
		}
	})
	if optErr != nil {
		t.Fatal(optErr)
	}
	return index
}

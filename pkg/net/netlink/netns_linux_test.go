//go:build !android

package netlink

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

const netNSHelperEnv = "YUH_NETNS_PROCESS_HELPER"

// TestNetNSProcessHelper runs inside a child network namespace. It opens a
// connected TCP pair and an unbound UDP socket for IPv4 and IPv6 on fixed
// ports, so separate namespaces can reuse identical addresses.
func TestNetNSProcessHelper(t *testing.T) {
	base, err := strconv.Atoi(os.Getenv(netNSHelperEnv))
	if err != nil {
		t.Skip("network namespace process helper")
	}
	if os.Getenv("YUH_NETNS_PROCESS_SETUP") == "1" {
		lo, err := netlink.LinkByName("lo")
		if err == nil {
			err = netlink.LinkSetUp(lo)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	var closers []io.Closer
	defer func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}()
	for _, host := range []string{"127.0.0.1", "::1"} {
		listener, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(base+1)))
		if err != nil {
			t.Fatal(err)
		}
		closers = append(closers, listener)
		dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(host), Port: base}}
		conn, err := dialer.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		closers = append(closers, conn)
		accepted, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		closers = append(closers, accepted)
		packet, err := net.ListenPacket("udp", net.JoinHostPort(host, strconv.Itoa(base+2)))
		if err != nil {
			t.Fatal(err)
		}
		closers = append(closers, packet)
	}
	peer := 0
	if peerBase := os.Getenv("YUH_NETNS_PROCESS_PEER"); peerBase != "" {
		// A second process in the same namespace, started by inheritance.
		child, ready := startNetNSHelper(t, peerBase, nil)
		<-ready
		peer = child.Process.Pid
	}
	fmt.Printf("READY peer=%d\n", peer)
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func startNetNSHelper(t testing.TB, base string, attr *syscall.SysProcAttr, env ...string) (*exec.Cmd, <-chan int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestNetNSProcessHelper$")
	// Later entries win, so env may override the defaults.
	cmd.Env = append(append(os.Environ(), netNSHelperEnv+"="+base, "YUH_NETNS_PROCESS_PEER="), env...)
	cmd.SysProcAttr = attr
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		if err := cmd.Wait(); err != nil {
			t.Logf("helper %d: %v", cmd.Process.Pid, err)
		}
	})
	ready := make(chan int, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if peer, ok := strings.CutPrefix(scanner.Text(), "READY peer="); ok {
				n, _ := strconv.Atoi(peer)
				ready <- n
				break
			}
		}
		_, _ = io.Copy(io.Discard, stdout)
	}()
	return cmd, ready
}

type netNSHelper struct {
	pid, peer int
	dumper    *NetNSProcessDumper
}

func startNamespacedHelper(t *testing.T, base int, withPeer bool) netNSHelper {
	t.Helper()
	env := []string{"YUH_NETNS_PROCESS_SETUP=1"}
	if withPeer {
		env = append(env, "YUH_NETNS_PROCESS_PEER="+strconv.Itoa(base+100))
	}
	cmd, ready := startNetNSHelper(t, strconv.Itoa(base), &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}, env...)
	var peer int
	select {
	case peer = <-ready:
	case <-time.After(20 * time.Second):
		t.Fatal("namespace helper did not start")
	}
	ns, err := os.Open("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	dumper, err := NewNetNSProcessDumper(ns)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dumper.Close() })
	return netNSHelper{pid: cmd.Process.Pid, peer: peer, dumper: dumper}
}

func requireNetNSPrivileges(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("creating and entering network namespaces requires root")
	}
}

type netNSQuery struct {
	name, network string
	src, dst      netip.AddrPort
}

func netNSQueries(base int) []netNSQuery {
	var queries []netNSQuery
	for _, host := range []string{"127.0.0.1", "::1"} {
		ip := netip.MustParseAddr(host)
		family := "4"
		if ip.Is6() {
			family = "6"
		}
		queries = append(queries,
			netNSQuery{"tcp" + family, "tcp", netip.AddrPortFrom(ip, uint16(base)), netip.AddrPortFrom(ip, uint16(base+1))},
			netNSQuery{"udp" + family, "udp", netip.AddrPortFrom(ip, uint16(base+2)), netip.AddrPortFrom(ip, 53)},
		)
	}
	return queries
}

func TestNetNSProcessDumperIdentifiesNamespaceSockets(t *testing.T) {
	requireNetNSPrivileges(t)
	const base = 41000
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Both namespaces bind identical addresses; A also hosts a peer process.
	a := startNamespacedHelper(t, base, true)
	b := startNamespacedHelper(t, base, false)
	if a.peer == 0 {
		t.Fatal("peer helper did not start in namespace A")
	}
	for _, q := range netNSQueries(base) {
		t.Run(q.name, func(t *testing.T) {
			for _, h := range []netNSHelper{a, b} {
				process, err := h.dumper.FindProcessName(q.network, q.src, q.dst)
				if err != nil {
					t.Fatalf("namespace of %d: %v", h.pid, err)
				}
				if process.Pid != uint(h.pid) || process.Path != executable || process.Uid != 0 {
					t.Fatalf("namespace of %d resolved %+v", h.pid, process)
				}
			}
			// The host namespace has no such socket and must not report a helper.
			if process, err := FindProcessName(q.network, q.src, q.dst); err == nil &&
				(process.Pid == uint(a.pid) || process.Pid == uint(b.pid)) {
				t.Fatalf("host lookup attributed a namespaced socket to %+v", process)
			}
		})
	}
	for _, q := range netNSQueries(base + 100) {
		t.Run("peer-"+q.name, func(t *testing.T) {
			process, err := a.dumper.FindProcessName(q.network, q.src, q.dst)
			if err != nil || process.Pid != uint(a.peer) {
				t.Fatalf("second process in namespace A: %+v %v", process, err)
			}
			// The peer exists only in A; B must not fall back to another namespace.
			if process, err := b.dumper.FindProcessName(q.network, q.src, q.dst); err == nil {
				t.Fatalf("namespace B resolved namespace A's peer socket: %+v", process)
			}
		})
	}
}

func TestNetNSProcessDumperCloseDuringLookup(t *testing.T) {
	requireNetNSPrivileges(t)
	const base = 42000
	h := startNamespacedHelper(t, base, false)
	queries := netNSQueries(base)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 16 {
		wg.Go(func() {
			<-start
			for j := range 50 {
				q := queries[(i+j)%len(queries)]
				process, err := h.dumper.FindProcessName(q.network, q.src, q.dst)
				if err == nil && process.Pid != uint(h.pid) {
					t.Errorf("lookup during close resolved %+v", process)
				}
				if err != nil && !errors.Is(err, net.ErrClosed) {
					t.Errorf("lookup during close: %v", err)
				}
			}
		})
	}
	close(start)
	time.Sleep(time.Millisecond)
	if err := h.dumper.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if _, err := h.dumper.FindProcessName("tcp", queries[0].src, queries[0].dst); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("lookup after close: %v", err)
	}
	if err := h.dumper.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestNetNSProcessDumperReleasesResources(t *testing.T) {
	requireNetNSPrivileges(t)
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	open := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	// Warm up lazily created runtime and package state before counting.
	if d, err := NewNetNSProcessDumper(ns); err == nil {
		_ = d.Close()
	}
	fds, goroutines := open(), runtime.NumGoroutine()
	for range 64 {
		d, err := NewNetNSProcessDumper(ns)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = d.FindProcessName("tcp", netip.MustParseAddrPort("127.0.0.1:1"), netip.MustParseAddrPort("127.0.0.1:2"))
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if got := open(); got != fds {
		t.Fatalf("open descriptors: %d before, %d after 64 dumpers", fds, got)
	}
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > goroutines && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > goroutines {
		t.Fatalf("goroutines: %d before, %d after 64 dumpers", goroutines, got)
	}
}

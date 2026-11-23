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
	"golang.org/x/sys/unix"
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
		// Hand a sock_diag socket of this namespace to the test process, the
		// way a session helper does, so the test never enters the namespace.
		diag, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_INET_DIAG)
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.Sendmsg(3, []byte{1}, unix.UnixRights(diag), nil, 0); err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(diag)
		_ = unix.Close(3)
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
		child, ready := startNetNSHelper(t, peerBase, nil, "YUH_NETNS_PROCESS_SETUP=0")
		<-ready
		peer = child.Process.Pid
	}
	fmt.Printf("READY peer=%d\n", peer)
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func startNetNSHelper(t testing.TB, base string, attr *syscall.SysProcAttr, env ...string) (*exec.Cmd, <-chan int) {
	return startNetNSHelperFiles(t, base, attr, nil, env...)
}

func startNetNSHelperFiles(t testing.TB, base string, attr *syscall.SysProcAttr, files []*os.File, env ...string) (*exec.Cmd, <-chan int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestNetNSProcessHelper$")
	cmd.ExtraFiles = files
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
	dumper    *SockDiagProcessDumper
}

// startNamespacedHelper creates a user and network namespace without any
// host privilege, receives its sock_diag socket over SCM_RIGHTS and builds
// a dumper from it.
func startNamespacedHelper(t *testing.T, base int, withPeer bool) netNSHelper {
	t.Helper()
	env := []string{"YUH_NETNS_PROCESS_SETUP=1"}
	if withPeer {
		env = append(env, "YUH_NETNS_PROCESS_PEER="+strconv.Itoa(base+100))
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent, child := os.NewFile(uintptr(fds[0]), "parent"), os.NewFile(uintptr(fds[1]), "child")
	defer parent.Close()
	uid, gid := os.Geteuid(), os.Getegid()
	attr := &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
		AmbientCaps: []uintptr{unix.CAP_NET_ADMIN},
	}
	cmd, ready := startNetNSHelperFiles(t, strconv.Itoa(base), attr, []*os.File{child}, env...)
	_ = child.Close()
	timeout := unix.NsecToTimeval((20 * time.Second).Nanoseconds())
	if err := unix.SetsockoptTimeval(int(parent.Fd()), unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		t.Fatal(err)
	}
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(int(parent.Fd()), make([]byte, 1), oob, unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(cmsgs) != 1 {
		t.Fatalf("no diag socket: %v", err)
	}
	received, err := unix.ParseUnixRights(&cmsgs[0])
	if err != nil || len(received) != 1 {
		t.Fatalf("no diag socket: %v", err)
	}
	var peer int
	select {
	case peer = <-ready:
	case <-time.After(20 * time.Second):
		t.Fatal("namespace helper did not start")
	}
	var stat unix.Stat_t
	if err := unix.Stat("/proc/"+strconv.Itoa(cmd.Process.Pid)+"/ns/net", &stat); err != nil {
		t.Fatal(err)
	}
	dumper, err := NewSockDiagProcessDumper(os.NewFile(uintptr(received[0]), "sock_diag"), stat.Ino)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dumper.Close() })
	return netNSHelper{pid: cmd.Process.Pid, peer: peer, dumper: dumper}
}

// requireUserNamespaces skips only when unprivileged user namespaces are
// unavailable; YUH_REQUIRE_ROOTLESS=1 turns that into a failure.
func requireUserNamespaces(t *testing.T) {
	t.Helper()
	uid, gid := os.Geteuid(), os.Getegid()
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
	}
	if err := cmd.Run(); err != nil {
		if os.Getenv("YUH_REQUIRE_ROOTLESS") == "1" {
			t.Fatalf("unprivileged user namespaces are required: %v", err)
		}
		t.Skipf("unprivileged user namespaces are unavailable: %v", err)
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

func TestSockDiagProcessDumperIdentifiesNamespaceSockets(t *testing.T) {
	requireUserNamespaces(t)
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
				if process.Pid != uint(h.pid) || process.Path != executable || process.Uid != uint(os.Geteuid()) {
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

func TestSockDiagProcessDumperCloseDuringLookup(t *testing.T) {
	requireUserNamespaces(t)
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

func TestSockDiagProcessDumperReleasesResources(t *testing.T) {
	var stat unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &stat); err != nil {
		t.Fatal(err)
	}
	newDumper := func() *SockDiagProcessDumper {
		fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_INET_DIAG)
		if err != nil {
			t.Fatal(err)
		}
		d, err := NewSockDiagProcessDumper(os.NewFile(uintptr(fd), "sock_diag"), stat.Ino)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	open := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	_ = newDumper().Close()
	fds, goroutines := open(), runtime.NumGoroutine()
	for range 64 {
		d := newDumper()
		_, _ = d.FindProcessName("tcp", netip.MustParseAddrPort("127.0.0.1:1"), netip.MustParseAddrPort("127.0.0.1:2"))
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if got := open(); got != fds {
		t.Fatalf("open descriptors: %d before, %d after 64 dumpers", fds, got)
	}
	if got := runtime.NumGoroutine(); got > goroutines {
		t.Fatalf("goroutines: %d before, %d after 64 dumpers", goroutines, got)
	}
}

func TestSockDiagProcessDumperRejectsOtherDescriptors(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if d, err := NewSockDiagProcessDumper(r, 1); err == nil {
		_ = d.Close()
		t.Fatal("a pipe was accepted as a sock_diag socket")
	}
}

// TestSockDiagProcessDumperHostSockets checks the exact-match ranking on
// real host sockets: connected TCP, dual-stack TCP and wildcard UDP.
func TestSockDiagProcessDumperHostSockets(t *testing.T) {
	var stat unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &stat); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_INET_DIAG)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewSockDiagProcessDumper(os.NewFile(uintptr(fd), "sock_diag"), stat.Ino)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "[::]:0") // dual-stack
	if err != nil {
		t.Skip("no IPv6 dual-stack sockets here")
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	conn, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	udp, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	client := netip.MustParseAddrPort(conn.LocalAddr().String())
	server := netip.MustParseAddrPort(conn.RemoteAddr().String())
	for _, q := range []struct {
		name, network string
		local, remote netip.AddrPort
	}{
		{"connected client", "tcp", client, server},
		{"dual-stack accepted", "tcp", server, client},
		{"wildcard udp", "udp", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(udp.LocalAddr().(*net.UDPAddr).Port)), netip.MustParseAddrPort("192.0.2.1:53")},
	} {
		process, err := d.FindProcessName(q.network, q.local, q.remote)
		if err != nil || process.Pid != uint(os.Getpid()) || process.Path != executable {
			t.Fatalf("%s: %+v %v", q.name, process, err)
		}
	}
	if _, err := d.FindProcessName("tcp", client, netip.MustParseAddrPort("127.0.0.1:1")); err == nil {
		t.Fatal("a different remote endpoint must not match a connected socket")
	}
}

//go:build !android

package netlink

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// The topology mirrors a Kubernetes node. The test process plays the node
// (and yuhaiin on it); a pod and a remote host each get a namespace:
//
//	pod 10.244.0.5 fd00:244::5 --veth-- node --veth-- remote 192.0.2.1 2001:db8::1
//
// The node forwards and masquerades flows to port natPort, as a CNI does,
// but not flows to directPort. Run as root, for example in a user namespace:
//
//	go test -c -o netlink.test && unshare -Urn --fork ./netlink.test -test.run Container
const (
	containerRoleEnv = "YUH_CONTAINER_TOPOLOGY_ROLE"
	natPort          = 22000
	directPort       = 23000
)

var (
	topoPod4    = netip.MustParseAddr("10.244.0.5")
	topoPod6    = netip.MustParseAddr("fd00:244::5")
	topoNode4   = netip.MustParseAddr("192.0.2.10")
	topoNode6   = netip.MustParseAddr("2001:db8::10")
	topoRemote4 = netip.MustParseAddr("192.0.2.1")
	topoRemote6 = netip.MustParseAddr("2001:db8::1")
)

// TestContainerTopologyHelper runs the pod or remote side.
func TestContainerTopologyHelper(t *testing.T) {
	switch os.Getenv(containerRoleEnv) {
	case "pod":
		runTopologyPod()
	case "remote":
		runTopologyRemote()
	default:
		t.Skip("container topology helper")
	}
	os.Exit(0)
}

// runTopologyPod opens sockets on request and keeps them until stdin closes.
// Commands are "tcp|udp <local port> <remote>"; UDP sockets stay unconnected,
// as a discovery service's would.
func runTopologyPod() {
	var keep []io.Closer
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		f := strings.Fields(in.Text())
		if len(f) != 3 {
			fmt.Println("ERR bad command")
			continue
		}
		port, _ := strconv.Atoi(f[1])
		remote := netip.MustParseAddrPort(f[2])
		local := netip.IPv4Unspecified()
		if remote.Addr().Is6() {
			local = netip.IPv6Unspecified()
		}
		var err error
		switch f[0] {
		case "tcp":
			var c net.Conn
			d := net.Dialer{LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(local, uint16(port))), Timeout: 5 * time.Second}
			if c, err = d.Dial("tcp", remote.String()); err == nil {
				keep = append(keep, c)
			}
		case "udp":
			var c *net.UDPConn
			if c, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, uint16(port)))); err == nil {
				keep = append(keep, c)
				_, err = c.WriteToUDPAddrPort([]byte("hello"), remote)
			}
		}
		if err != nil {
			fmt.Println("ERR", err)
		} else {
			fmt.Println("OK")
		}
	}
	for _, c := range keep {
		_ = c.Close()
	}
}

// runTopologyRemote reports the source address of every flow it receives.
func runTopologyRemote() {
	out := make(chan string, 64)
	for _, port := range []int{natPort, directPort} {
		l, err := net.Listen("tcp", ":"+strconv.Itoa(port))
		if err != nil {
			fmt.Println("ERR", err)
			return
		}
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				out <- fmt.Sprintf("PEER tcp %d %s", port, c.RemoteAddr())
			}
		}()
		p, err := net.ListenPacket("udp", ":"+strconv.Itoa(port))
		if err != nil {
			fmt.Println("ERR", err)
			return
		}
		go func() {
			buf := make([]byte, 64)
			for {
				_, from, err := p.ReadFrom(buf)
				if err != nil {
					return
				}
				out <- fmt.Sprintf("PEER udp %d %s", port, from)
			}
		}()
	}
	fmt.Println("READY")
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); os.Exit(0) }()
	for line := range out {
		fmt.Println(line)
	}
}

type topologyProc struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	lines chan string
}

func startTopologyProc(t testing.TB, role string) *topologyProc {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestContainerTopologyHelper$")
	cmd.Env = append(os.Environ(), containerRoleEnv+"="+role)
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
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
	p := &topologyProc{cmd: cmd, stdin: stdin, lines: make(chan string, 64)}
	go func() {
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			p.lines <- s.Text()
		}
		close(p.lines)
	}()
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	return p
}

func (p *topologyProc) expect(t testing.TB, prefix string) string {
	t.Helper()
	select {
	case line, ok := <-p.lines:
		if !ok || !strings.HasPrefix(line, prefix) {
			t.Fatalf("pid %d: got %q, want %q", p.cmd.Process.Pid, line, prefix)
		}
		return line
	case <-time.After(10 * time.Second):
		t.Fatalf("pid %d: timed out waiting for %q", p.cmd.Process.Pid, prefix)
	}
	return ""
}

func requireNodeRoot(t testing.TB) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("the container topology needs root, for example: unshare -Urn --fork ./netlink.test")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft is required to masquerade")
	}
}

// veth connects the node to the namespace of pid and assigns addresses.
func veth(t testing.TB, name string, pid int, nodeAddrs, peerAddrs []netip.Prefix, peerRoutes []netip.Addr) {
	t.Helper()
	link := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: name + "p"}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	peer, err := netlink.LinkByName(name + "p")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetNsPid(peer, pid); err != nil {
		t.Fatal(err)
	}
	for _, p := range nodeAddrs {
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: prefixNet(p), Flags: unix.IFA_F_NODAD}); err != nil {
			t.Fatal(err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	ns, err := netns.GetFromPid(pid)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	inner, err := h.LinkByName(name + "p")
	if err != nil {
		t.Fatal(err)
	}
	lo, err := h.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []netlink.Link{lo, inner} {
		if err := h.LinkSetUp(l); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range peerAddrs {
		if err := h.AddrAdd(inner, &netlink.Addr{IPNet: prefixNet(p), Flags: unix.IFA_F_NODAD}); err != nil {
			t.Fatal(err)
		}
	}
	for _, gw := range peerRoutes {
		if err := h.RouteAdd(&netlink.Route{LinkIndex: inner.Attrs().Index, Gw: gw.AsSlice()}); err != nil {
			t.Fatal(err)
		}
	}
}

func prefixNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

type topology struct {
	pod, remote *topologyProc
}

func startTopology(t testing.TB) *topology {
	t.Helper()
	if lo, err := netlink.LinkByName("lo"); err != nil || netlink.LinkSetUp(lo) != nil {
		t.Fatal("bring up lo", err)
	}
	pod := startTopologyProc(t, "pod")
	remote := startTopologyProc(t, "remote")
	remote.expect(t, "READY")
	veth(t, "vpod", pod.cmd.Process.Pid,
		[]netip.Prefix{netip.MustParsePrefix("10.244.0.1/24"), netip.MustParsePrefix("fd00:244::1/64")},
		[]netip.Prefix{netip.PrefixFrom(topoPod4, 24), netip.PrefixFrom(topoPod6, 64)},
		[]netip.Addr{netip.MustParseAddr("10.244.0.1"), netip.MustParseAddr("fd00:244::1")})
	// The remote routes pod addresses back through the node, so flows that
	// are not masqueraded still work.
	veth(t, "vrem", remote.cmd.Process.Pid,
		[]netip.Prefix{netip.PrefixFrom(topoNode4, 24), netip.PrefixFrom(topoNode6, 64)},
		[]netip.Prefix{netip.PrefixFrom(topoRemote4, 24), netip.PrefixFrom(topoRemote6, 64)},
		[]netip.Addr{topoNode4, topoNode6})
	for _, f := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		if err := os.WriteFile(f, []byte("1"), 0); err != nil {
			t.Fatal(err)
		}
	}
	rules := fmt.Sprintf(`table inet yuhaiin_test {
	chain postrouting {
		type nat hook postrouting priority srcnat;
		oifname "vrem" ip saddr 10.244.0.0/24 meta l4proto { tcp, udp } th dport %[1]d masquerade
		oifname "vrem" ip6 saddr fd00:244::/64 meta l4proto { tcp, udp } th dport %[1]d masquerade
	}
}`, natPort)
	nft := exec.Command("nft", "-f", "-")
	nft.Stdin = strings.NewReader(rules)
	if out, err := nft.CombinedOutput(); err != nil {
		t.Fatalf("nft: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", "yuhaiin_test").Run() })
	return &topology{pod: pod, remote: remote}
}

// open makes the pod open a flow and returns its source as the remote saw it,
// which is also what the node observes after masquerading.
func (tp *topology) open(t testing.TB, network string, localPort int, remote netip.AddrPort) netip.AddrPort {
	t.Helper()
	fmt.Fprintf(tp.pod.stdin, "%s %d %s\n", network, localPort, remote)
	tp.pod.expect(t, "OK")
	line := tp.remote.expect(t, fmt.Sprintf("PEER %s %d ", network, remote.Port()))
	f := strings.Fields(line)
	observed := netip.MustParseAddrPort(f[3])
	return netip.AddrPortFrom(observed.Addr().Unmap(), observed.Port())
}

func TestContainerProcessDumperResolvesPodFlows(t *testing.T) {
	requireNodeRoot(t)
	tp := startTopology(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewContainerProcessDumper()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if d.conntrack.Load() == nil {
		t.Fatal("conntrack resolver unavailable")
	}

	type flow struct {
		name    string
		network string
		port    int
		remote  netip.AddrPort
		natted  bool
	}
	var flows []flow
	for i, remote := range []netip.Addr{topoRemote4, topoRemote6} {
		family := []string{"4", "6"}[i]
		for j, network := range []string{"tcp", "udp"} {
			base := 41000 + i*10 + j
			flows = append(flows,
				flow{"nat-" + network + family, network, base, netip.AddrPortFrom(remote, natPort), true},
				flow{"direct-" + network + family, network, base + 100, netip.AddrPortFrom(remote, directPort), false},
			)
		}
	}
	// A host service bound to the wildcard address on the pod's ports, as when
	// the same program runs on the node and in a pod: an unconnected UDP
	// socket matches any source address on its port.
	for _, f := range flows {
		if f.network != "udp" {
			continue
		}
		host := "0.0.0.0"
		if f.remote.Addr().Is6() {
			host = "::"
		}
		c, err := net.ListenPacket("udp", net.JoinHostPort(host, strconv.Itoa(f.port)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
	}

	for _, f := range flows {
		t.Run(f.name, func(t *testing.T) {
			observed := tp.open(t, f.network, f.port, f.remote)
			pod := topoPod4
			if f.remote.Addr().Is6() {
				pod = topoPod6
			}
			if f.natted && observed.Addr() == pod {
				t.Fatalf("flow was not masqueraded: %s", observed)
			}
			if !f.natted && observed != netip.AddrPortFrom(pod, uint16(f.port)) {
				t.Fatalf("direct flow arrived from %s", observed)
			}
			if p, err := FindProcessName(f.network, observed, f.remote); err == nil {
				t.Logf("host-only lookup of %s: pid %d (%s)", observed, p.Pid, p.Path)
			}
			p, err := d.FindProcessName(f.network, observed, f.remote)
			if err != nil {
				t.Fatalf("%s -> %s: %v", observed, f.remote, err)
			}
			if p.Pid != uint(tp.pod.cmd.Process.Pid) || p.Path != executable {
				t.Fatalf("%s -> %s resolved to %+v, want pod pid %d", observed, f.remote, p, tp.pod.cmd.Process.Pid)
			}
		})
	}

	// Flows of the node itself still resolve on the host, from loopback and
	// from a node address.
	for _, host := range []netip.Addr{netip.MustParseAddr("127.0.0.1"), topoNode4, topoNode6} {
		t.Run("host-"+host.String(), func(t *testing.T) {
			l, err := net.Listen("tcp", netip.AddrPortFrom(host, 0).String())
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			c, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			local := netip.MustParseAddrPort(c.LocalAddr().String())
			p, err := d.FindProcessName("tcp", local, netip.MustParseAddrPort(l.Addr().String()))
			if err != nil || p.Pid != uint(os.Getpid()) {
				t.Fatalf("host flow: %+v %v", p, err)
			}
		})
	}
}

// BenchmarkContainerProcessDumper measures one lookup per path on the real
// kernel: a host flow, and pod flows with and without masquerade.
func BenchmarkContainerProcessDumper(b *testing.B) {
	requireNodeRoot(b)
	tp := startTopology(b)
	d, err := NewContainerProcessDumper()
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = d.Close() })
	nat := netip.AddrPortFrom(topoRemote4, natPort)
	direct := netip.AddrPortFrom(topoRemote4, directPort)
	natted := tp.open(b, "tcp", 42001, nat)
	unnatted := tp.open(b, "tcp", 42002, direct)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	hostSrc := netip.MustParseAddrPort(c.LocalAddr().String())
	hostDst := netip.MustParseAddrPort(l.Addr().String())

	for _, bc := range []struct {
		name     string
		src, dst netip.AddrPort
		lookup   func(string, netip.AddrPort, netip.AddrPort) error
	}{
		{"host/host-only", hostSrc, hostDst, func(n string, s, d netip.AddrPort) error { _, err := FindProcessName(n, s, d); return err }},
		{"host/container-aware", hostSrc, hostDst, func(n string, s, dd netip.AddrPort) error { _, err := d.FindProcessName(n, s, dd); return err }},
		{"pod-direct", unnatted, direct, func(n string, s, dd netip.AddrPort) error { _, err := d.FindProcessName(n, s, dd); return err }},
		{"pod-masqueraded", natted, nat, func(n string, s, dd netip.AddrPort) error { _, err := d.FindProcessName(n, s, dd); return err }},
	} {
		b.Run(bc.name, func(b *testing.B) {
			for b.Loop() {
				if err := bc.lookup("tcp", bc.src, bc.dst); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
	b.Run("conntrack-get", func(b *testing.B) {
		ct := d.conntrack.Load()
		for b.Loop() {
			if _, _, ok, err := ct.original(unix.IPPROTO_TCP, natted, nat); !ok || err != nil {
				b.Fatal(ok, err)
			}
		}
	})
}

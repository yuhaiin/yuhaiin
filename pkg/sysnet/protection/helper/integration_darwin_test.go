package helper

// Real packet filter tests for macOS. They load rules into the real PF,
// add the managed lines to /etc/pf.conf, create utun devices and routes for
// documentation prefixes, and take PF references. They therefore only run
// with YUHAIIN_TEST_PF=1 as root, on a disposable machine (CI runner or VM):
//
//	go test -c -o helper.test ./pkg/sysnet/protection/helper
//	sudo YUHAIIN_TEST_PF=1 ./helper.test -test.run TestPF -test.v
//
// Every test restores /etc/pf.conf byte for byte, removes only what it
// created and checks that other anchors and references are unchanged. The
// Internet connections the machine already has (the CI runner's) and its
// DNS servers are added as bypass networks so the runner stays connected.
//
// How verdicts are observed: test destinations are routed into utun
// devices this test owns, so a packet PF lets through is read back from the
// utun file descriptor, and a packet PF blocks makes the send fail
// (EHOSTUNREACH) and never arrives. Direct Internet traffic is checked on
// the physical interface with tcpdump.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/policy"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/pf"
	"golang.org/x/sys/unix"
)

func requireLivePF(t *testing.T) {
	t.Helper()
	if os.Getenv("YUHAIIN_TEST_PF") != "1" || os.Geteuid() != 0 {
		t.Skip("set YUHAIIN_TEST_PF=1 and run as root on a disposable macOS machine")
	}
}

func sh(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func firstLine(s string) string {
	for l := range strings.SplitSeq(s, "\n") {
		if strings.HasPrefix(l, "Status:") {
			return l
		}
	}
	return s
}

// anchorRules counts the rules in the protection anchor (pfctl prints
// ALTQ warnings before them).
func anchorRules() int {
	return len(pf.ParseRules(shQuiet("/sbin/pfctl", "-a", pf.ProtectionAnchor, "-s", "rules")))
}

func shQuiet(name string, args ...string) string {
	out, _ := exec.Command(name, args...).CombinedOutput()
	return string(out)
}

// utun is a utun device owned by the test.
type utun struct {
	fd   int
	name string
}

func openUtun(t *testing.T) *utun {
	t.Helper()
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, unix.AF_SYS_CONTROL)
	if err != nil {
		t.Fatal(err)
	}
	info := &unix.CtlInfo{}
	copy(info.Name[:], "com.apple.net.utun_control")
	if err := unix.IoctlCtlInfo(fd, info); err != nil {
		t.Fatal(err)
	}
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: 0}); err != nil {
		t.Fatal(err)
	}
	name, err := unix.GetsockoptString(fd, 2 /* SYSPROTO_CONTROL */, 2 /* UTUN_OPT_IFNAME */)
	if err != nil {
		t.Fatal(err)
	}
	u := &utun{fd: fd, name: strings.TrimRight(name, "\x00")}
	t.Cleanup(u.close)
	return u
}

func (u *utun) close() {
	if u.fd >= 0 {
		unix.Close(u.fd)
		u.fd = -1
	}
}

// received reports whether a packet to dst arrives on the device within
// timeout.
func (u *utun) received(dst netip.Addr, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 65536)
	for time.Now().Before(deadline) {
		fds := []unix.PollFd{{Fd: int32(u.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, int(time.Until(deadline)/time.Millisecond)+1)
		if err != nil || n == 0 {
			continue
		}
		size, err := unix.Read(u.fd, buf)
		if err != nil || size < 4+20 {
			continue
		}
		pkt := buf[4:size]
		var got netip.Addr
		switch pkt[0] >> 4 {
		case 4:
			got = netip.AddrFrom4([4]byte(pkt[16:20]))
		case 6:
			if len(pkt) >= 40 {
				got = netip.AddrFrom16([16]byte(pkt[24:40]))
			}
		}
		if got == dst {
			return true
		}
	}
	return false
}

func (u *utun) drain() {
	_ = unix.SetNonblock(u.fd, true)
	buf := make([]byte, 65536)
	for {
		if _, err := unix.Read(u.fd, buf); err != nil {
			break
		}
	}
	_ = unix.SetNonblock(u.fd, false)
}

// send writes one UDP datagram and returns the send error. PF blocking an
// outgoing packet fails the send.
func send(dst string) error {
	conn, err := net.Dial("udp", net.JoinHostPort(dst, "9"))
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte("yuhaiin-pf-test"))
	return err
}

type verdict struct {
	dev  *utun
	dst  string
	pass bool
}

func checkVerdicts(t *testing.T, step string, list []verdict) {
	t.Helper()
	for _, v := range list {
		v.dev.drain()
		err := send(v.dst)
		arrived := err == nil && v.dev.received(netip.MustParseAddr(v.dst), 1500*time.Millisecond)
		if arrived != v.pass {
			t.Errorf("%s: %s via %s: passed=%v (send error %v), want passed=%v", step, v.dst, v.dev.name, arrived, err, v.pass)
		}
	}
}

// machinePeers returns the remote addresses of current TCP connections and
// the DNS servers, so the CI runner keeps working while protection is on.
func machinePeers() []netip.Prefix {
	var out []netip.Prefix
	add := func(s string) {
		if a, err := netip.ParseAddr(s); err == nil && !a.IsLoopback() && !a.IsPrivate() && !a.IsLinkLocalUnicast() && !a.IsUnspecified() {
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
		}
	}
	for line := range strings.SplitSeq(shQuiet("/usr/sbin/netstat", "-an", "-p", "tcp"), "\n") {
		f := strings.Fields(line)
		if len(f) >= 6 && f[5] == "ESTABLISHED" {
			if i := strings.LastIndexByte(f[4], '.'); i > 0 {
				add(f[4][:i])
			}
		}
	}
	for line := range strings.SplitSeq(shQuiet("/usr/sbin/scutil", "--dns"), "\n") {
		if _, v, ok := strings.Cut(line, "nameserver["); ok {
			if _, addr, ok := strings.Cut(v, ":"); ok {
				add(strings.TrimSpace(addr))
			}
		}
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	return slices.Compact(out)
}

type liveEnv struct {
	t        *testing.T
	conf     string
	cfg      Config
	cancel   context.CancelFunc
	done     chan error
	foreign  string
	yuhaiin  *utun
	other    *utun
	physical string
	peers    []netip.Prefix
	gid      int
}

func newLiveEnv(t *testing.T) *liveEnv {
	requireLivePF(t)
	ctx := context.Background()
	orig, err := os.ReadFile("/etc/pf.conf")
	if err != nil {
		t.Fatal(err)
	}
	if pf.Registered(string(orig)).Managed {
		t.Fatal("/etc/pf.conf already has Yuhaiin's lines; refusing to run on a machine that uses Network Protection")
	}
	dir, err := os.MkdirTemp("", "ypf")
	if err != nil {
		t.Fatal(err)
	}
	e := &liveEnv{t: t, conf: string(orig)}
	engine := pf.NewEngine(filepath.Join(dir, "state"))
	e.cfg = Config{StateFile: filepath.Join(dir, "state", "state.json"), Socket: filepath.Join(dir, "p.sock"), Engine: engine,
		BootID: BootID, Group: EnsureGroup, PeerUID: PeerUID, Verify: time.Second}
	e.gid, err = EnsureGroup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("socket group %s = %d", GroupName, e.gid)
	beforeRefs := shQuiet("/sbin/pfctl", "-s", "References")
	t.Logf("PF before:\n%s\n%s", shQuiet("/sbin/pfctl", "-s", "info"), beforeRefs)
	// Another program's anchor and reference, which must survive.
	foreignRules := "block out proto udp to 192.0.2.250 port 4\n"
	cmd := exec.Command("/sbin/pfctl", "-a", "org.example.yuhaiin-test", "-f", "-")
	cmd.Stdin = strings.NewReader(foreignRules)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("foreign anchor: %v %s", err, out)
	}
	e.foreign = pf.ParseToken(sh(t, "/sbin/pfctl", "-E"))
	if e.foreign == "" {
		t.Fatal("no foreign token")
	}
	t.Logf("References after foreign -E:\n%s", shQuiet("/sbin/pfctl", "-s", "References"))

	route := shQuiet("/sbin/route", "-n", "get", "default")
	for line := range strings.SplitSeq(route, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "interface:"); ok {
			e.physical = strings.TrimSpace(v)
		}
	}
	e.peers = machinePeers()
	t.Logf("physical interface %s, runner peers kept reachable: %v", e.physical, e.peers)

	e.yuhaiin, e.other = openUtun(t), openUtun(t)
	sh(t, "/sbin/ifconfig", e.yuhaiin.name, "inet", "10.201.0.1", "10.201.0.2", "up")
	sh(t, "/sbin/ifconfig", e.yuhaiin.name, "inet6", "fd00:201::1", "prefixlen", "64")
	sh(t, "/sbin/ifconfig", e.other.name, "inet", "10.202.0.1", "10.202.0.2", "up")
	sh(t, "/sbin/ifconfig", e.other.name, "inet6", "fd00:202::1", "prefixlen", "64")
	routes := [][]string{
		{"-net", "192.0.2.0/24", "-interface", e.yuhaiin.name},
		{"-inet6", "-net", "2001:db8:99::/48", "-interface", e.yuhaiin.name},
		{"-net", "198.51.100.0/24", "-interface", e.other.name},
		{"-net", "203.0.113.0/24", "-interface", e.other.name},
		{"-net", "10.255.0.0/24", "-interface", e.other.name},
		{"-inet6", "-net", "2001:db8:77::/48", "-interface", e.other.name},
		{"-inet6", "-net", "fd00:78::/48", "-interface", e.other.name},
	}
	for _, r := range routes {
		sh(t, "/sbin/route", append([]string{"-n", "add"}, r...)...)
	}
	t.Cleanup(func() {
		e.stop()
		for _, r := range routes {
			_ = exec.Command("/sbin/route", append([]string{"-n", "delete"}, r...)...).Run()
		}
		// Remove what the test created, in the recovery's way.
		rc := Recovery{StateFile: e.cfg.StateFile, Engine: engine, BootID: BootID, Euid: os.Geteuid}
		if r := rc.Run(ctx); !r.Success {
			t.Errorf("cleanup recovery: %+v", r)
		}
		if _, err := engine.Unregister(ctx); err != nil {
			t.Errorf("unregister: %v", err)
		}
		now, _ := os.ReadFile("/etc/pf.conf")
		if string(now) != e.conf {
			t.Errorf("/etc/pf.conf not restored:\n%s", now)
			_ = pf.WriteFileAtomic("/etc/pf.conf", []byte(e.conf), 0o644)
		}
		_ = exec.Command("/sbin/pfctl", "-f", "/etc/pf.conf").Run()
		if got := shQuiet("/sbin/pfctl", "-a", "org.example.yuhaiin-test", "-s", "rules"); !strings.Contains(got, "192.0.2.250") {
			t.Errorf("foreign anchor changed: %q", got)
		}
		_ = exec.Command("/sbin/pfctl", "-a", "org.example.yuhaiin-test", "-F", "rules").Run()
		_ = exec.Command("/sbin/pfctl", "-X", e.foreign).Run()
		t.Logf("PF after:\n%s\n%s", shQuiet("/sbin/pfctl", "-s", "info"), shQuiet("/sbin/pfctl", "-s", "References"))
		os.RemoveAll(dir)
	})
	return e
}

func (e *liveEnv) start() {
	s := NewServer(e.cfg)
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel, e.done = cancel, make(chan error, 1)
	go func() { e.done <- s.Run(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if c, err := net.Dial("unix", e.cfg.Socket); err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			e.t.Fatal("service did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (e *liveEnv) stop() {
	if e.cancel != nil {
		e.cancel()
		if err := <-e.done; err != nil {
			e.t.Logf("service: %v", err)
		}
		e.cancel = nil
	}
}

func (e *liveEnv) policy() protection.Policy {
	return protection.Policy{Mode: sysnet.ProtectionModeStandard, StartAtBoot: true, PrivateNetworks: policy.PrivateNetworks(),
		BypassNetworks: append([]netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, e.peers...),
		Tunnels:        []protection.Tunnel{{Name: e.yuhaiin.name, IPv4: true, IPv6: true}}, OwnTraffic: true}
}

func (e *liveEnv) baseVerdicts(tunnel bool) []verdict {
	return []verdict{
		{e.yuhaiin, "192.0.2.10", tunnel},      // public IPv4 through the Yuhaiin TUN
		{e.yuhaiin, "2001:db8:99::10", tunnel}, // public IPv6 through the Yuhaiin TUN
		{e.other, "198.51.100.10", false},      // public IPv4 through an unrelated utun
		{e.other, "2001:db8:77::10", false},    // public IPv6 through an unrelated utun
		{e.other, "10.255.0.10", true},         // private IPv4
		{e.other, "fd00:78::10", true},         // private IPv6 (ULA)
		{e.other, "203.0.113.10", true},        // explicit bypass
	}
}

// ownSend sends from a socket created with the Yuhaiin socket group.
func ownSend(t *testing.T, gid int, dst string) error {
	t.Helper()
	if err := syscall.Setgid(gid); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Setgid(0) }()
	return send(dst)
}

// capture counts packets to dst on the physical interface while f runs.
func capture(t *testing.T, iface, dst string, f func()) int {
	t.Helper()
	file := filepath.Join(t.TempDir(), "cap.pcap")
	cmd := exec.Command("/usr/sbin/tcpdump", "-i", iface, "-n", "-U", "-w", file, "dst", "host", dst)
	if err := cmd.Start(); err != nil {
		t.Logf("tcpdump unavailable: %v", err)
		f()
		return -1
	}
	time.Sleep(1500 * time.Millisecond)
	f()
	time.Sleep(1500 * time.Millisecond)
	_ = cmd.Process.Signal(os.Interrupt)
	_ = cmd.Wait()
	out, _ := exec.Command("/usr/sbin/tcpdump", "-n", "-r", file).Output()
	return bytes.Count(out, []byte("\n"))
}

func TestPFKillSwitch(t *testing.T) {
	e := newLiveEnv(t)
	ctx := context.Background()

	// Before protection everything passes.
	checkVerdicts(t, "off", []verdict{{e.other, "198.51.100.11", true}, {e.yuhaiin, "192.0.2.11", true}})

	e.start()
	client := newClientAt(e.cfg.Socket, "api")
	defer client.Close()
	p := e.policy()
	st, err := client.Call(ctx, OpEnable, &p)
	if err != nil {
		t.Fatalf("enable: %v\n%+v", err, st)
	}
	t.Logf("anchor rules:\n%s", shQuiet("/sbin/pfctl", "-a", pf.ProtectionAnchor, "-v", "-s", "rules"))
	t.Logf("main rules:\n%s", shQuiet("/sbin/pfctl", "-s", "rules"))
	if st.State != sysnet.ProtectionProtected || !st.Effective || !st.OwnTraffic.Allowed {
		t.Fatalf("status after enable: %+v", st)
	}
	if !strings.Contains(shQuiet("/sbin/pfctl", "-s", "rules"), `anchor "io.github.yuhaiin/*"`) {
		t.Fatal("main ruleset does not reference the anchor")
	}
	conf, _ := os.ReadFile("/etc/pf.conf")
	if !pf.Registered(string(conf)).Filter {
		t.Fatal("pf.conf not registered")
	}

	t.Run("verdicts", func(t *testing.T) { checkVerdicts(t, "protected", e.baseVerdicts(true)) })
	t.Run("direct traffic blocked on the physical interface", func(t *testing.T) {
		// UDP sends succeed locally with "block return" (PF answers with
		// ICMP); what matters is that nothing leaves the interface.
		if n := capture(t, e.physical, "1.1.1.1", func() { _ = send("1.1.1.1") }); n != 0 {
			t.Fatalf("direct IPv4 leaked: %d packets on %s", n, e.physical)
		}
		if n := capture(t, e.physical, "2606:4700:4700::1111", func() { _ = send("2606:4700:4700::1111") }); n != 0 {
			t.Fatalf("direct IPv6 leaked: %d packets on %s", n, e.physical)
		}
		// TCP gets a reset from PF at once instead of a connection.
		conn, err := net.DialTimeout("tcp", "1.1.1.1:443", 3*time.Second)
		if err == nil {
			conn.Close()
			t.Fatal("direct TCP connected")
		}
		t.Logf("direct TCP refused as expected: %v", err)
	})
	t.Run("Yuhaiin's own sockets pass", func(t *testing.T) {
		var sendErr error
		n := capture(t, e.physical, "1.1.1.1", func() { sendErr = ownSend(t, e.gid, "1.1.1.1") })
		if sendErr != nil || n == 0 {
			t.Fatalf("own traffic: send error %v, %d packets on %s", sendErr, n, e.physical)
		}
	})
	t.Run("blocked counters", func(t *testing.T) {
		st, err := client.Call(ctx, OpStatus, nil)
		if err != nil || st.Blocked == nil || st.Blocked.Packets == 0 {
			t.Fatalf("blocked counters: %+v %v", st.Blocked, err)
		}
		if st.OwnTraffic.Connections != nil {
			t.Logf("blocked %d packets, own connections %d", st.Blocked.Packets, *st.OwnTraffic.Connections)
		}
	})
	t.Run("pf.conf reload keeps the rules", func(t *testing.T) {
		before := pf.LoadedID(pf.ParseRules(shQuiet("/sbin/pfctl", "-a", pf.ProtectionAnchor, "-v", "-s", "rules")))
		sh(t, "/sbin/pfctl", "-f", "/etc/pf.conf")
		after := pf.LoadedID(pf.ParseRules(shQuiet("/sbin/pfctl", "-a", pf.ProtectionAnchor, "-v", "-s", "rules")))
		if before == "" || before != after {
			t.Fatalf("reloading pf.conf changed the anchor: %q -> %q", before, after)
		}
		checkVerdicts(t, "after pf.conf reload", e.baseVerdicts(true)[:3])
	})
	t.Run("invalid update keeps rules", func(t *testing.T) {
		bad := e.policy()
		bad.Tunnels = []protection.Tunnel{{Name: "utun0 all"}}
		if _, err := client.Call(ctx, OpUpdate, &bad); err == nil {
			t.Fatal("invalid policy accepted")
		}
		checkVerdicts(t, "after rejected update", e.baseVerdicts(true)[:3])
	})
	t.Run("core killed", func(t *testing.T) {
		// A separate process takes over the core session and is killed
		// with SIGKILL: its allowances end, the block stays.
		child := exec.Command(os.Args[0], "-test.run", "^TestPFChildCore$")
		child.Env = append(os.Environ(), "YUHAIIN_PF_CHILD="+e.cfg.Socket, "YUHAIIN_PF_CHILD_TUN="+e.yuhaiin.name)
		stdout, _ := child.StdoutPipe()
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		if line, _ := bufio.NewReader(stdout).ReadString('\n'); !strings.Contains(line, "ready") {
			t.Fatalf("child: %q", line)
		}
		client.Close() // the child's session is the only one
		checkVerdicts(t, "child core", e.baseVerdicts(true)[:1])
		_ = child.Process.Signal(syscall.SIGKILL)
		_ = child.Wait()
		waitFor(t, func() bool {
			return !strings.Contains(shQuiet("/sbin/pfctl", "-a", pf.ProtectionAnchor, "-s", "rules"), e.yuhaiin.name)
		})
		checkVerdicts(t, "core killed", e.baseVerdicts(false))
		if n := capture(t, e.physical, "1.1.1.1", func() { _ = ownSend(t, e.gid, "1.1.1.1") }); n != 0 {
			t.Fatalf("own traffic still allowed after the core died: %d packets", n)
		}
	})
	t.Run("TUN removed", func(t *testing.T) {
		p := e.policy()
		if _, err := client.Call(ctx, OpUpdate, &p); err != nil {
			t.Fatal(err)
		}
		checkVerdicts(t, "core back", e.baseVerdicts(true)[:1])
		e.yuhaiin.close()
		// The route through it is gone: the destination now goes to the
		// physical interface and must be blocked there.
		waitFor(t, func() bool {
			return !strings.Contains(shQuiet("/sbin/pfctl", "-a", pf.ProtectionAnchor, "-s", "rules"), e.yuhaiin.name)
		})
		if n := capture(t, e.physical, "192.0.2.10", func() { _ = send("192.0.2.10") }); n != 0 {
			t.Fatalf("traffic of a removed TUN leaked to the physical interface: %d packets", n)
		}
	})
	t.Run("service restart", func(t *testing.T) {
		e.stop()
		stopped := []verdict{{e.other, "198.51.100.20", false}, {e.other, "10.255.0.20", true}}
		checkVerdicts(t, "service stopped", stopped)
		e.start()
		st, err := newClientAt(e.cfg.Socket, "cli").Call(ctx, OpStatus, nil)
		if err != nil || st.State != sysnet.ProtectionProtected {
			t.Fatalf("after restart: %+v %v", st, err)
		}
	})
	t.Run("other program disables PF", func(t *testing.T) {
		// Not something Yuhaiin ever does: simulates another tool.
		t.Logf("pfctl -d: %s", shQuiet("/sbin/pfctl", "-d"))
		t.Logf("after -d: %s\n%s", firstLine(shQuiet("/sbin/pfctl", "-s", "info")), shQuiet("/sbin/pfctl", "-s", "References"))
		deadline := time.Now().Add(10 * time.Second)
		for {
			on, _ := pf.ParseEnabled(shQuiet("/sbin/pfctl", "-s", "info"))
			blocked := false
			if on {
				e.other.drain()
				_ = send("198.51.100.21")
				blocked = !e.other.received(netip.MustParseAddr("198.51.100.21"), time.Second)
			}
			if blocked {
				break
			}
			if time.Now().After(deadline) {
				s, _, _ := LoadState(e.cfg.StateFile)
				t.Fatalf("not blocking again after PF was disabled by another program: enabled=%v token=%s\n%s\n%s\n%s", on, s.Token,
					firstLine(shQuiet("/sbin/pfctl", "-s", "info")), shQuiet("/sbin/pfctl", "-s", "References"), shQuiet("/sbin/pfctl", "-a", pf.ProtectionAnchor, "-s", "rules"))
			}
			time.Sleep(300 * time.Millisecond)
		}
		t.Logf("blocking again: %s\n%s", firstLine(shQuiet("/sbin/pfctl", "-s", "info")), shQuiet("/sbin/pfctl", "-s", "References"))
		// The foreign reference was dropped by -d; take it again.
		e.foreign = pf.ParseToken(sh(t, "/sbin/pfctl", "-E"))
	})
	t.Run("disable", func(t *testing.T) {
		c := newClientAt(e.cfg.Socket, "cli")
		defer c.Close()
		st, err := c.Call(ctx, OpDisable, nil)
		if err != nil || st.State != sysnet.ProtectionDisabled || st.Effective {
			t.Fatalf("disable: %+v %v", st, err)
		}
		if n := anchorRules(); n != 0 {
			t.Fatalf("%d rules left after disable", n)
		}
		refs := shQuiet("/sbin/pfctl", "-s", "References")
		if !strings.Contains(refs, e.foreign) {
			t.Fatalf("foreign reference released:\n%s", refs)
		}
		if on, _ := pf.ParseEnabled(shQuiet("/sbin/pfctl", "-s", "info")); !on {
			t.Fatal("PF turned off although another program holds a reference")
		}
		checkVerdicts(t, "disabled", []verdict{{e.other, "198.51.100.30", true}})
	})
	t.Run("recovery and reboot", func(t *testing.T) {
		c := newClientAt(e.cfg.Socket, "api")
		p := e.policy()
		p.Tunnels = nil
		if _, err := c.Call(ctx, OpEnable, &p); err != nil {
			t.Fatal(err)
		}
		c.Close()
		e.stop() // the service is broken or gone
		rc := Recovery{StateFile: e.cfg.StateFile, Engine: e.cfg.Engine, BootID: BootID, Euid: os.Geteuid}
		report := rc.Run(ctx)
		for _, s := range report.Steps {
			t.Logf("recovery step %+v", s)
		}
		if !report.Success {
			t.Fatal("recovery failed")
		}
		checkVerdicts(t, "after recovery", []verdict{{e.other, "198.51.100.31", true}})
		if !strings.Contains(shQuiet("/sbin/pfctl", "-s", "References"), e.foreign) {
			t.Fatal("recovery released another program's reference")
		}
		// A new boot session: the service starts and keeps protection off.
		e.cfg.BootID = func() string { return "next-boot" }
		e.start()
		st, err := newClientAt(e.cfg.Socket, "cli").Call(ctx, OpStatus, nil)
		if err != nil || st.Desired.Enabled || st.Effective {
			t.Fatalf("after simulated reboot: %+v %v", st, err)
		}
		e.cfg.BootID = BootID
	})
}

// TestPFChildCore is the child process of the "core killed" test.
func TestPFChildCore(t *testing.T) {
	socket := os.Getenv("YUHAIIN_PF_CHILD")
	if socket == "" {
		t.Skip("helper process")
	}
	c := newClientAt(socket, "api")
	p := protection.Policy{Mode: sysnet.ProtectionModeStandard, StartAtBoot: true, PrivateNetworks: policy.PrivateNetworks(),
		BypassNetworks: append([]netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, machinePeers()...),
		Tunnels:        []protection.Tunnel{{Name: os.Getenv("YUHAIIN_PF_CHILD_TUN"), IPv4: true, IPv6: true}}, OwnTraffic: true}
	if _, err := c.Call(context.Background(), OpUpdate, &p); err != nil {
		fmt.Println("error", err)
		os.Exit(1)
	}
	fmt.Println("ready")
	time.Sleep(time.Hour)
}

// TestPFCommandLine runs the real yuhaiin binary against the real service
// under launchd: status, disable, and the emergency recovery while the
// service is stopped. YUHAIIN_TEST_BINARY is the built yuhaiin binary.
func TestPFCommandLine(t *testing.T) {
	requireLivePF(t)
	binary := os.Getenv("YUHAIIN_TEST_BINARY")
	if binary == "" {
		t.Skip("set YUHAIIN_TEST_BINARY to a built yuhaiin binary")
	}
	ctx := context.Background()
	orig, _ := os.ReadFile("/etc/pf.conf")
	if _, err := os.Stat(Binary); err == nil {
		t.Fatalf("%s exists; refusing to replace an installed Yuhaiin", Binary)
	}
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Dir(Binary), 0o755)
	if err := os.WriteFile(Binary, data, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		out, err := exec.Command(Binary, "protection", "disable", "--recovery", "--yes").CombinedOutput()
		t.Logf("cleanup recovery: %v\n%s", err, out)
		_ = UninstallDaemon(ctx)
		_, _ = pf.NewEngine(StateDir).Unregister(ctx)
		_ = os.RemoveAll(StateDir)
		_ = os.Remove(Binary)
		if now, _ := os.ReadFile("/etc/pf.conf"); !bytes.Equal(now, orig) {
			t.Errorf("/etc/pf.conf not restored")
			_ = pf.WriteFileAtomic("/etc/pf.conf", orig, 0o644)
			_ = exec.Command("/sbin/pfctl", "-f", "/etc/pf.conf").Run()
		}
	})
	if err := InstallDaemon(ctx, Binary); err != nil {
		t.Fatal(err)
	}
	cli := func(args ...string) (string, int) {
		cmd := exec.Command(Binary, args...)
		out, err := cmd.CombinedOutput()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
		t.Logf("$ yuhaiin %s (exit %d)\n%s", strings.Join(args, " "), code, out)
		return string(out), code
	}
	enable := func() {
		c := NewClient("api")
		defer c.Close()
		p := protection.Policy{Mode: sysnet.ProtectionModeStandard, StartAtBoot: true, PrivateNetworks: policy.PrivateNetworks(), BypassNetworks: machinePeers()}
		if _, err := c.Call(ctx, OpEnable, &p); err != nil {
			t.Fatal(err)
		}
	}
	enable()
	if out, code := cli("protection", "status"); code != 0 || !strings.Contains(out, "Status: Protected") || !strings.Contains(out, "Privileged Helper: Running") {
		t.Fatal("status")
	}
	// Without root: status is readable, disable is refused.
	if user := os.Getenv("SUDO_USER"); user != "" {
		out, _ := exec.Command("/usr/bin/sudo", "-u", user, Binary, "protection", "status").CombinedOutput()
		t.Logf("$ sudo -u %s yuhaiin protection status\n%s", user, out)
		if !strings.Contains(string(out), "Status: Protected") {
			t.Errorf("non-root status:\n%s", out)
		}
		out, err := exec.Command("/usr/bin/sudo", "-u", user, Binary, "protection", "disable", "--yes").CombinedOutput()
		t.Logf("$ sudo -u %s yuhaiin protection disable --yes (%v)\n%s", user, err, out)
		if err == nil || !strings.Contains(string(out), "administrator") {
			t.Errorf("non-root disable:\n%s %v", out, err)
		}
	}
	if out, code := cli("protection", "disable", "--yes"); code != 0 || !strings.Contains(out, "disabled") {
		t.Fatal("disable")
	}
	if out, _ := cli("protection", "status"); !strings.Contains(out, "Status: Disabled") {
		t.Fatal("not disabled")
	}
	// Idempotent on an empty anchor.
	if _, code := cli("protection", "disable", "--yes"); code != 0 {
		t.Fatal("second disable")
	}
	enable()
	if err := StopDaemon(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(shQuiet("/sbin/pfctl", "-a", pf.ProtectionAnchor, "-s", "rules"), "block") {
		t.Fatal("protection lost when the service stopped")
	}
	if out, code := cli("protection", "disable", "--yes"); code == 0 || !strings.Contains(out, "--recovery") {
		t.Fatal("disable without the service did not suggest recovery")
	}
	if out, code := cli("protection", "status"); code != 0 || !strings.Contains(out, "Not reachable") {
		t.Fatal("offline status")
	}
	if out, code := cli("protection", "disable", "--recovery", "--yes"); code != 0 || !strings.Contains(out, "stay disabled") {
		t.Fatal("recovery")
	}
	if n := anchorRules(); n != 0 {
		t.Fatalf("%d rules left after recovery", n)
	}
	// "Reboot": launchd starts the service again; protection stays off.
	if err := EnsureDaemon(ctx); err != nil {
		t.Fatal(err)
	}
	if out, _ := cli("protection", "status"); !strings.Contains(out, "Status: Disabled") || !strings.Contains(out, "Privileged Helper: Running") {
		t.Fatal("protection came back after recovery")
	}
}

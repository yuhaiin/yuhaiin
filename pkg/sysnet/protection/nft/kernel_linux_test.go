//go:build linux && !android

package nft

// Real kernel tests. They change nftables, interfaces and routes, so they
// only run with YUHAIIN_TEST_NFT=1 as root in a disposable network
// namespace (scripts/integration/network-protection-podman.sh runs them in
// a privileged container; the host is not touched).
//
// Verdicts are read from interface transmit counters: a packet the kill
// switch lets through is counted on the interface it leaves by, a rejected
// one never reaches it.

import (
	"context"
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
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/policy"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/helper"
	"golang.org/x/sys/unix"
)

func requireKernel(t *testing.T) {
	t.Helper()
	if os.Getenv("YUHAIIN_TEST_NFT") != "1" || os.Geteuid() != 0 {
		t.Skip("set YUHAIIN_TEST_NFT=1 and run as root in a disposable network namespace")
	}
}

func run(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return string(out)
}

// openTun creates a TUN device that exists while the returned file is open.
func openTun(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	var req [unix.IFNAMSIZ + 64]byte
	copy(req[:], name)
	*(*uint16)(unsafe.Pointer(&req[unix.IFNAMSIZ])) = unix.IFF_TUN | unix.IFF_NO_PI
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.TUNSETIFF, uintptr(unsafe.Pointer(&req[0]))); errno != 0 {
		t.Fatal(errno)
	}
	run(t, "ip", "link", "set", name, "up")
	tuns[name] = f
	return f
}

func txPackets(t *testing.T, dev string) int {
	t.Helper()
	data, err := os.ReadFile("/sys/class/net/" + dev + "/statistics/tx_packets")
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return n
}

// tuns maps TUN names to their open device files. A TUN counts transmitted
// packets only once they are read, so its verdicts are read from the file.
var tuns = map[string]*os.File{}

func readsPacket(f *os.File, dst string) bool {
	want := netip.MustParseAddr(dst)
	buf := make([]byte, 2048)
	_ = f.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	for {
		n, err := f.Read(buf)
		if err != nil {
			return false
		}
		if n >= 20 && buf[0]>>4 == 4 && netip.AddrFrom4([4]byte(buf[16:20])) == want {
			return true
		}
	}
}

// leaves reports whether a UDP datagram to dst leaves through dev.
func leaves(t *testing.T, dev, dst string, mark int) bool {
	t.Helper()
	tun := tuns[dev]
	before := 0
	if tun == nil {
		before = txPackets(t, dev)
	}
	d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		if mark == 0 {
			return nil
		}
		var serr error
		_ = c.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark) })
		return serr
	}}
	conn, err := d.Dial("udp", net.JoinHostPort(dst, "9"))
	if err != nil {
		return false
	}
	_, _ = conn.Write([]byte("yuhaiin-nft-test"))
	conn.Close()
	if tun != nil {
		return readsPacket(tun, dst)
	}
	time.Sleep(50 * time.Millisecond)
	return txPackets(t, dev) > before
}

type verdict struct {
	dev, dst string
	mark     int
	pass     bool
}

func check(t *testing.T, step string, list []verdict) {
	t.Helper()
	for _, v := range list {
		if got := leaves(t, v.dev, v.dst, v.mark); got != v.pass {
			t.Errorf("%s: %s via %s (mark %#x): passed=%v, want %v", step, v.dst, v.dev, v.mark, got, v.pass)
		}
	}
}

func kernelPolicy() protection.Policy {
	return protection.Policy{Mode: sysnet.ProtectionModeStandard, PrivateNetworks: policy.PrivateNetworks(),
		BypassNetworks: []netip.Prefix{netip.MustParsePrefix("203.0.113.192/26"), netip.MustParsePrefix("2001:db8:5:1::/64")},
		Tunnels:        []protection.Tunnel{{Name: "ytun0", IPv4: true}}, OwnTraffic: true}
}

func TestKernelKillSwitch(t *testing.T) {
	requireKernel(t)
	run(t, "ip", "link", "add", "dum0", "type", "dummy")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "dum0").Run() })
	run(t, "ip", "addr", "add", "198.18.0.2/24", "dev", "dum0")
	run(t, "ip", "link", "set", "dum0", "up")
	for _, r := range []string{"203.0.113.0/24", "100.64.1.0/24"} {
		run(t, "ip", "route", "add", r, "dev", "dum0")
	}
	v6 := exec.Command("ip", "-6", "addr", "add", "fd00:9::2/64", "dev", "dum0", "nodad").Run() == nil
	if v6 {
		run(t, "ip", "-6", "route", "add", "2001:db8:5::/48", "dev", "dum0")
		run(t, "ip", "-6", "route", "add", "fd00:5::/64", "dev", "dum0")
	}
	tun0, tun1 := openTun(t, "ytun0"), openTun(t, "ytun1")
	defer tun1.Close()
	run(t, "ip", "route", "add", "192.0.2.0/24", "dev", "ytun0")
	run(t, "ip", "route", "add", "198.51.100.0/24", "dev", "ytun1")

	all := []verdict{
		{"dum0", "203.0.113.10", 0, false},    // public, direct
		{"dum0", "203.0.113.200", 0, true},    // explicit bypass
		{"dum0", "100.64.1.5", 0, true},       // private (shared address space)
		{"dum0", "203.0.113.10", 0x500, true}, // Yuhaiin's own socket
		{"dum0", "203.0.113.10", 0x501, false},
		{"ytun0", "192.0.2.9", 0, true},     // Yuhaiin TUN
		{"ytun1", "198.51.100.9", 0, false}, // another program's TUN
	}
	if v6 {
		all = append(all, verdict{"dum0", "2001:db8:5::1", 0, false}, verdict{"dum0", "2001:db8:5:1::1", 0, true}, verdict{"dum0", "fd00:5::1", 0, true})
	}
	check(t, "before protection", []verdict{{"dum0", "203.0.113.10", 0, true}, {"ytun1", "198.51.100.9", 0, true}})

	// A connection opened before protection (like the web interface's).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- c
		}
	}()
	early, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer early.Close()
	server := <-accepted
	defer server.Close()

	// Another program's table, which must keep working and stay untouched.
	foreign := "table inet foreign_test {\n chain out {\n  type filter hook output priority 10; policy accept;\n  ip daddr 100.64.1.6 drop\n  accept\n }\n}\n"
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(foreign)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("foreign table: %v %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", "foreign_test").Run() })

	ifc, _ := net.InterfaceByName("ytun0")
	plan, err := Compile(kernelPolicy(), Env{Tunnels: []Tunnel{{Name: "ytun0", Index: ifc.Index}}, OwnMark: 0x500})
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(plan); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Remove() })
	t.Logf("table:\n%s", run(t, "nft", "list", "table", "inet", Table))

	check(t, "protected", all)
	// Another table's accept does not pass blocked traffic, and its drop
	// still blocks traffic Yuhaiin allows.
	check(t, "with another firewall", []verdict{{"dum0", "100.64.1.6", 0, false}})

	_ = early.SetDeadline(time.Now().Add(2 * time.Second))
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := early.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatalf("existing connection cut: %v", err)
	}

	in := Inspect()
	if !in.Exists || LoadedID(labels(in)) != plan.ID {
		t.Fatalf("inspect: %+v", in)
	}
	var blocked uint64
	for _, r := range in.Rules {
		if Category(r.Label) == sysnet.RuleBlock {
			blocked += r.Packets
		}
	}
	if blocked == 0 {
		t.Fatal("block counter did not count")
	}
	if got := in.Sets["bypass4"]; len(got) != 1 || got[0] != "203.0.113.192/26" {
		t.Fatalf("bypass4 = %v", got)
	}

	snap := Snapshot(context.Background(), plan)
	marked := 0
	for _, m := range snap.Main {
		if m.Yuhaiin {
			marked++
		}
	}
	if marked != 1 || len(snap.Main) < 2 || len(snap.Rulesets[0].Rules) != len(plan.Rules) || !strings.Contains(snap.Raw, "foreign_test") {
		t.Fatalf("snapshot: %+v", snap)
	}

	// The TUN disappears and another program creates one with the same
	// name: it is a new interface (new index) and does not pass.
	tun0.Close()
	time.Sleep(100 * time.Millisecond)
	again := openTun(t, "ytun0")
	defer again.Close()
	run(t, "ip", "route", "replace", "192.0.2.0/24", "dev", "ytun0")
	check(t, "TUN name reused", []verdict{{"ytun0", "192.0.2.9", 0, false}})

	// A rejected update keeps the loaded table.
	bad := plan
	bad.Rules = append([]Rule{{Label: "x", Set: "missing", Verdict: "accept"}}, plan.Rules...)
	if err := Apply(bad); err == nil {
		t.Fatal("invalid update accepted")
	}
	if LoadedID(labels(Inspect())) != plan.ID {
		t.Fatal("previous rules lost after a rejected update")
	}

	if err := Remove(); err != nil {
		t.Fatal(err)
	}
	if Inspect().Exists || !strings.Contains(run(t, "nft", "list", "tables"), "foreign_test") {
		t.Fatal("remove did not remove only Yuhaiin's table")
	}
	check(t, "removed", []verdict{{"dum0", "203.0.113.10", 0, true}})
}

func TestKernelBackendAndRecovery(t *testing.T) {
	requireKernel(t)
	_ = os.RemoveAll(StateDir)
	t.Cleanup(func() { _ = Remove(); _ = os.RemoveAll(StateDir) })
	b := NewBackend(func() uint32 { return 0x500 })
	ctx := context.Background()
	st, err := b.Status(ctx)
	if err != nil || st.State != sysnet.ProtectionDisabled {
		t.Fatalf("initial: %+v %v", st, err)
	}
	p := kernelPolicy()
	p.Tunnels = nil
	p.StartAtBoot = true
	if err := b.Enable(ctx, p); err != nil {
		t.Fatal(err)
	}
	st, _ = b.Status(ctx)
	if !st.Effective || st.Backend != "nftables" || !st.Desired.Enabled {
		t.Fatalf("after enable: %+v", st)
	}
	// Another program deletes the table: status reports it and asks the
	// controller to apply again (a new session).
	session := b.Session()
	if err := Remove(); err != nil {
		t.Fatal(err)
	}
	if st, _ := b.Status(ctx); st.Effective || b.Session() == session {
		t.Fatalf("missing table not detected: %+v", st)
	}
	if err := b.Update(ctx, p); err != nil || !Inspect().Exists {
		t.Fatalf("not restored: %v", err)
	}
	// Restoring at boot loads the saved baseline.
	_ = Remove()
	if err := RestoreAtBoot(); err != nil || !Inspect().Exists {
		t.Fatalf("boot restore: %v", err)
	}
	// Recovery without the core.
	report := Recover(ctx)
	for _, s := range report.Steps {
		t.Logf("%+v", s)
	}
	if !report.Success || Inspect().Exists {
		t.Fatal("recovery failed")
	}
	if s, _, _ := helper.LoadState(StateFile); s.Enabled {
		t.Fatal("state still enabled")
	}
	if err := RestoreAtBoot(); err != nil || Inspect().Exists {
		t.Fatal("protection came back at boot after recovery")
	}
	if again := Recover(ctx); !again.Success {
		t.Fatal("recovery is not idempotent")
	}
}

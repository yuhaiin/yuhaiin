//go:build windows

package wfp

// Real Windows Filtering Platform tests. They add filters to the system's
// filtering engine, so they only run with YUHAIIN_TEST_WFP=1 as
// administrator on a disposable machine (CI runner or VM):
//
//	go test -c -o wfp.test.exe ./pkg/sysnet/protection/wfp
//	$env:YUHAIIN_TEST_WFP=1; .\wfp.test.exe -test.run TestWFP -test.v
//
// Verdicts: a connection the kill switch blocks fails at once with
// WSAEACCES (10013). The checks run in a copy of the test binary under
// another name, which has another application ID than this process, so
// Yuhaiin's own-traffic permit does not apply to it.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/policy"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/helper"
	"golang.org/x/sys/windows"
)

func requireWFP(t *testing.T) {
	t.Helper()
	if os.Getenv("YUHAIIN_TEST_WFP") != "1" || !Elevated() {
		t.Skip("set YUHAIIN_TEST_WFP=1 and run as administrator on a disposable machine")
	}
}

// dial returns "blocked", "allowed" or the error.
func dial(addr string) string {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err == nil {
		c.Close()
		return "allowed"
	}
	if errors.Is(err, windows.WSAEACCES) {
		return "blocked"
	}
	return "other: " + err.Error()
}

// TestWFPChild is the other application of the verdict checks.
func TestWFPChild(t *testing.T) {
	addr := os.Getenv("YUHAIIN_WFP_DIAL")
	if addr == "" {
		t.Skip("helper process")
	}
	fmt.Println("result:", dial(addr))
}

type checker struct {
	t     *testing.T
	child string
}

func newChecker(t *testing.T) *checker {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(t.TempDir(), "other-app.exe")
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(child, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return &checker{t: t, child: child}
}

func (c *checker) other(addr string) string {
	cmd := exec.Command(c.child, "-test.run", "^TestWFPChild$")
	cmd.Env = append(os.Environ(), "YUHAIIN_WFP_DIAL="+addr)
	out, _ := cmd.CombinedOutput()
	for line := range strings.SplitSeq(string(out), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "result: "); ok {
			return v
		}
	}
	return "no result: " + string(out)
}

func (c *checker) expect(step, who, addr string, blocked bool) {
	c.t.Helper()
	var got string
	if who == "self" {
		got = dial(addr)
	} else {
		got = c.other(addr)
	}
	if (got == "blocked") != blocked {
		c.t.Errorf("%s: %s -> %s: %s, want blocked=%v", step, who, addr, got, blocked)
	}
}

// machinePeers keeps the CI runner's connections and DNS reachable.
func machinePeers() []netip.Prefix {
	var out []netip.Prefix
	add := func(s string) {
		if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil && !a.IsLoopback() && !a.IsPrivate() && !a.IsUnspecified() && !a.IsLinkLocalUnicast() {
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
		}
	}
	if text, err := exec.Command("netstat", "-n", "-p", "TCP").Output(); err == nil {
		for line := range strings.SplitSeq(string(text), "\n") {
			f := strings.Fields(line)
			if len(f) >= 4 && f[3] == "ESTABLISHED" {
				if host, _, err := net.SplitHostPort(f[2]); err == nil {
					add(host)
				}
			}
		}
	}
	if text, err := exec.Command("powershell", "-NoProfile", "-Command", "(Get-DnsClientServerAddress).ServerAddresses").Output(); err == nil {
		for line := range strings.SplitSeq(string(text), "\n") {
			add(strings.TrimSpace(line))
		}
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	return slices.Compact(out)
}

func othersRules(t *testing.T, e *Engine) int {
	rules, err := e.base.Rules()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range rules {
		if r.Provider != ProviderID {
			n++
		}
	}
	return n
}

func TestWFPKillSwitch(t *testing.T) {
	requireWFP(t)
	ctx := context.Background()
	c := newChecker(t)
	probe, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	_ = probe.Remove()
	foreign := othersRules(t, probe)
	_ = os.RemoveAll(StateDir())
	t.Cleanup(func() {
		_ = probe.Remove()
		_ = os.RemoveAll(StateDir())
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, conn); conn.Close() }()
		}
	}()
	// A connection opened before protection must keep working.
	early, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer early.Close()

	c.expect("before protection", "other", "1.1.1.1:443", false)

	b := NewBackend()
	p := protection.Policy{Mode: sysnet.ProtectionModeStandard, StartAtBoot: true, PrivateNetworks: policy.PrivateNetworks(),
		BypassNetworks: append([]netip.Prefix{netip.MustParsePrefix("1.0.0.1/32")}, machinePeers()...), OwnTraffic: true}
	if err := b.Enable(ctx, p); err != nil {
		t.Fatal(err)
	}
	st, err := b.Status(ctx)
	if err != nil || !st.Effective || st.State != sysnet.ProtectionProtected || !st.OwnTraffic.Allowed || st.Backend != "wfp" {
		t.Fatalf("status after enable: %+v %v", st, err)
	}
	rules, _ := probe.Ours()
	for _, r := range rules {
		t.Logf("filter %s persistent=%v weight=%d", r.Name, r.Persistent, r.Weight)
	}

	c.expect("protected", "other", "1.1.1.1:443", true)       // public, another application
	c.expect("protected", "other", "1.0.0.1:443", false)      // explicit bypass
	c.expect("protected", "other", ln.Addr().String(), false) // loopback
	c.expect("protected", "other", "10.255.255.1:9", false)   // private (times out, not blocked)
	c.expect("protected", "self", "1.1.1.1:443", false)       // Yuhaiin's own executable
	if _, err := early.Write([]byte("still open")); err != nil {
		t.Fatalf("existing connection cut: %v", err)
	}

	// Persistent baseline: applied by the filtering engine at boot.
	persistentBlocks, runtimeOwn := 0, 0
	for _, r := range rules {
		if r.Description == blockLabel && r.Persistent {
			persistentBlocks++
		}
		if r.Description == labelPrefix+"own" {
			runtimeOwn++
			if r.Persistent {
				t.Error("runtime filter is persistent")
			}
		}
	}
	if persistentBlocks != 2 || runtimeOwn != 2 {
		t.Fatalf("persistent blocks %d, own permits %d", persistentBlocks, runtimeOwn)
	}

	// Yuhaiin exits: Windows deletes the dynamic session's permits, the
	// baseline stays.
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	rules, _ = probe.Ours()
	for _, r := range rules {
		if r.Description == labelPrefix+"own" {
			t.Fatal("own-traffic permit outlived the process session")
		}
	}
	c.expect("Yuhaiin stopped", "self", "1.1.1.1:443", true)
	c.expect("Yuhaiin stopped", "other", "1.0.0.1:443", false)

	// A new process restores the runtime part.
	b2 := NewBackend()
	defer b2.Close()
	if err := b2.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	c.expect("restarted", "self", "1.1.1.1:443", false)

	// Another program deletes Yuhaiin's filters: status reports it and
	// asks for a new sync.
	session := b2.Session()
	_ = probe.Remove()
	if st, _ := b2.Status(ctx); st.Effective || b2.Session() == session {
		t.Fatalf("missing filters not detected: %+v", st)
	}
	if err := b2.Update(ctx, p); err != nil {
		t.Fatal(err)
	}

	snap := b2.Rules(ctx)
	if !snap.Available || len(snap.Rulesets[0].Rules) == 0 || !slices.ContainsFunc(snap.Main, func(m sysnet.ProtectionMainRule) bool { return m.Yuhaiin }) {
		t.Fatalf("rules view: %+v", snap)
	}

	if err := b2.Disable(ctx); err != nil {
		t.Fatal(err)
	}
	if left, _ := probe.Ours(); len(left) != 0 {
		t.Fatalf("%d filters left after disable", len(left))
	}
	if othersRules(t, probe) != foreign {
		t.Fatal("other programs' filters changed")
	}
	c.expect("disabled", "other", "1.1.1.1:443", false)
}

// TestWFPRecovery runs the real yuhaiin.exe emergency recovery while
// protection is on and no Yuhaiin process runs.
func TestWFPRecovery(t *testing.T) {
	requireWFP(t)
	binary := os.Getenv("YUHAIIN_TEST_BINARY")
	if binary == "" {
		t.Skip("set YUHAIIN_TEST_BINARY to a built yuhaiin.exe")
	}
	ctx := context.Background()
	_ = os.RemoveAll(StateDir())
	t.Cleanup(func() { _ = os.RemoveAll(StateDir()) })
	b := NewBackend()
	p := protection.Policy{Mode: sysnet.ProtectionModeStandard, StartAtBoot: true, PrivateNetworks: policy.PrivateNetworks(), BypassNetworks: machinePeers()}
	if err := b.Enable(ctx, p); err != nil {
		t.Fatal(err)
	}
	b.Close()
	run := func(args ...string) (string, int) {
		cmd := exec.Command(binary, args...)
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := errors.AsType[*exec.ExitError](err); ok {
			code = ee.ExitCode()
		}
		t.Logf("$ yuhaiin %s (exit %d)\n%s", strings.Join(args, " "), code, out)
		return string(out), code
	}
	if out, code := run("protection", "status"); code != 0 || !strings.Contains(out, "Status: Protected") || !strings.Contains(out, "Windows Filtering Platform") {
		t.Fatal("status")
	}
	if out, code := run("protection", "disable", "--recovery", "--yes"); code != 0 || !strings.Contains(out, "stay disabled") {
		t.Fatal("recovery")
	}
	e, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if left, _ := e.Ours(); len(left) != 0 {
		t.Fatalf("%d filters left after recovery", len(left))
	}
	if s, _, _ := helper.LoadState(stateFile()); s.Enabled {
		t.Fatal("state still enabled")
	}
	if _, code := run("protection", "disable", "--recovery", "--yes"); code != 0 {
		t.Fatal("recovery is not idempotent")
	}
	if out, _ := run("protection", "status"); !strings.Contains(out, "Status: Disabled") {
		t.Fatal("status after recovery")
	}
}

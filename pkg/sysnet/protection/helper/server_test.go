package helper

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/iface"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/policy"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/pf"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/pf/pftest"
)

const testConf = "scrub-anchor \"com.apple/*\"\nnat-anchor \"com.apple/*\"\nrdr-anchor \"com.apple/*\"\ndummynet-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\nload anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"\n"

type harness struct {
	t      *testing.T
	dir    string
	fake   *pftest.Fake
	engine *pf.Engine
	boot   atomic.Value
	uid    atomic.Int64
	ifaces []iface.Info
	mu     sync.Mutex

	cancel context.CancelFunc
	done   chan error
	cfg    Config
}

func newHarness(t *testing.T) *harness {
	dir, err := os.MkdirTemp("", "yp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	h := &harness{t: t, dir: dir, fake: pftest.New()}
	h.boot.Store("boot-1")
	h.engine = &pf.Engine{Pfctl: "/sbin/pfctl", Conf: filepath.Join(dir, "pf.conf"), BackupDir: filepath.Join(dir, "state"), Anchor: pf.ProtectionAnchor, Run: h.fake.Run}
	if err := os.WriteFile(h.engine.Conf, []byte(testConf), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _ = h.fake.Run(context.Background(), "", "/sbin/pfctl", "-f", h.engine.Conf)
	h.ifaces = []iface.Info{{Name: "lo0", Index: 1, Type: iface.TypeLoopback, Up: true}, {Name: "en0", Index: 4, Type: iface.TypeWiFi, Up: true},
		{Name: "utun4", Index: 20, Type: iface.TypeTunnel, Up: true}, {Name: "utun9", Index: 21, Type: iface.TypeTunnel, Up: true}}
	h.cfg = Config{
		StateFile: filepath.Join(dir, "state", "state.json"), Socket: filepath.Join(dir, "p.sock"), Engine: h.engine,
		BootID: func() string { return h.boot.Load().(string) }, Group: func(context.Context) (int, error) { return 345, nil },
		Interfaces: func() ([]iface.Info, error) { h.mu.Lock(); defer h.mu.Unlock(); return slices.Clone(h.ifaces), nil },
		PeerUID:    func(net.Conn) (int, error) { return int(h.uid.Load()), nil },
		Verify:     time.Hour,
	}
	return h
}

func (h *harness) start() *Server {
	s := NewServer(h.cfg)
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel, h.done = cancel, make(chan error, 1)
	go func() { h.done <- s.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if c, err := net.Dial("unix", h.cfg.Socket); err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			h.t.Fatal("service did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Cleanup(h.stop)
	return s
}

// stop ends the service without any cleanup, like a crash or SIGKILL:
// whatever it loaded stays in the (fake) kernel.
func (h *harness) stop() {
	if h.cancel != nil {
		h.cancel()
		if err := <-h.done; err != nil {
			h.t.Logf("service: %v", err)
		}
		h.cancel = nil
	}
}

func (h *harness) client() *Client {
	c := newClientAt(h.cfg.Socket, "api")
	h.t.Cleanup(func() { c.Close() })
	return c
}

func testPolicy() protection.Policy {
	return protection.Policy{Mode: sysnet.ProtectionModeStandard, StartAtBoot: true, PrivateNetworks: policy.PrivateNetworks(),
		BypassNetworks: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		Tunnels:        []protection.Tunnel{{Name: "utun4", IPv4: true, IPv6: true}}, OwnTraffic: true}
}

func (h *harness) loaded() string { return h.fake.Loaded(pf.ProtectionAnchor) }

func mustState(t *testing.T, path string) State {
	t.Helper()
	s, _, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEnableProtectsAndCoreLeaseEnds(t *testing.T) {
	h := newHarness(t)
	h.start()
	foreign, _ := h.fake.Run(context.Background(), "", "/sbin/pfctl", "-E")
	c := h.client()
	ctx := context.Background()
	p := testPolicy()
	st, err := c.Call(ctx, OpEnable, &p)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != sysnet.ProtectionProtected || !st.Effective || !st.Desired.Enabled || !*st.Filter.Enabled || !*st.Filter.Registered || !*st.Filter.Loaded || !*st.Filter.Persistent {
		t.Fatalf("status = %+v", st)
	}
	if !slices.Equal(st.TunnelInterfaces, []string{"utun4"}) || !st.OwnTraffic.Allowed || st.OwnTraffic.GroupID != 345 || st.BypassCount != 1 {
		t.Fatalf("runtime = %+v", st)
	}
	if !slices.Contains(st.PhysicalInterfaces, "en0") || slices.Contains(st.PhysicalInterfaces, "utun4") || slices.Contains(st.PhysicalInterfaces, "lo0") {
		t.Fatalf("physical = %v", st.PhysicalInterfaces)
	}
	rules := h.loaded()
	if !strings.Contains(rules, "on utun4 ") || !strings.Contains(rules, "group 345") || strings.Contains(rules, "utun9") {
		t.Fatalf("rules = %s", rules)
	}
	saved := mustState(t, h.cfg.StateFile)
	if !saved.Enabled || saved.Token == "" || saved.AppliedBoot != "boot-1" || len(saved.Policy.Tunnels) != 0 || saved.Policy.OwnTraffic {
		t.Fatalf("saved = %+v", saved)
	}
	if st.Filter.Reference == nil || !*st.Filter.Reference {
		t.Fatal("reference not reported")
	}
	// The core disappears: its TUN and sockets lose their allowance, the
	// block stays.
	c.Close()
	waitFor(t, func() bool {
		r := h.loaded()
		return r != "" && !strings.Contains(r, "utun4") && !strings.Contains(r, "group")
	})
	st2, err := h.client().Call(ctx, OpStatus, nil)
	if err != nil || st2.State != sysnet.ProtectionProtected || len(st2.TunnelInterfaces) != 0 || st2.OwnTraffic.Allowed {
		t.Fatalf("after disconnect: %+v %v", st2, err)
	}
	if !slices.Contains(h.fake.Tokens, strings.TrimSpace(strings.TrimPrefix(foreign[strings.Index(foreign, ":")+1:], " "))) {
		t.Fatal("foreign reference lost")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNonRootCannotChange(t *testing.T) {
	h := newHarness(t)
	h.uid.Store(501)
	h.start()
	p := testPolicy()
	if _, err := h.client().Call(context.Background(), OpEnable, &p); err == nil || !strings.Contains(err.Error(), "administrator") {
		t.Fatalf("err = %v", err)
	}
	if _, err := h.client().Call(context.Background(), OpDisable, nil); err == nil {
		t.Fatal("non-root disabled")
	}
	st, err := h.client().Call(context.Background(), OpStatus, nil)
	if err != nil || st.State != sysnet.ProtectionDisabled {
		t.Fatalf("status for non-root: %+v %v", st, err)
	}
	if h.loaded() != "" {
		t.Fatal("rules loaded")
	}
}

func TestUpdateNeverEnables(t *testing.T) {
	h := newHarness(t)
	h.start()
	p := testPolicy()
	st, err := h.client().Call(context.Background(), OpUpdate, &p)
	if err != nil || st.Desired.Enabled || h.loaded() != "" {
		t.Fatalf("update enabled protection: %+v %v", st, err)
	}
}

func TestDisableSavesStateBeforeRemovingRules(t *testing.T) {
	h := newHarness(t)
	h.start()
	c := h.client()
	ctx := context.Background()
	p := testPolicy()
	if _, err := c.Call(ctx, OpEnable, &p); err != nil {
		t.Fatal(err)
	}
	other, _ := h.fake.Run(ctx, "", "/sbin/pfctl", "-E")
	var orderErr error
	h.fake.OnCall = func(call string) {
		if strings.Contains(call, "-a "+pf.ProtectionAnchor+" -F rules") {
			if s, _, _ := LoadState(h.cfg.StateFile); s.Enabled {
				orderErr = errors.New("rules removed before the disabled state was saved")
			}
		}
	}
	st, err := c.Call(ctx, OpDisable, nil)
	h.fake.OnCall = nil
	if err != nil || orderErr != nil {
		t.Fatal(err, orderErr)
	}
	if st.State != sysnet.ProtectionDisabled || st.Effective || *st.Filter.Loaded || h.loaded() != "" {
		t.Fatalf("status = %+v", st)
	}
	saved := mustState(t, h.cfg.StateFile)
	if saved.Enabled || saved.Token != "" || saved.ChangedBy != "api" {
		t.Fatalf("saved = %+v", saved)
	}
	// Yuhaiin's reference is gone, the other program's is kept, PF stays on.
	if len(h.fake.Tokens) != 1 || !strings.Contains(other, h.fake.Tokens[0]) || !h.fake.Enabled {
		t.Fatalf("tokens = %v enabled %v", h.fake.Tokens, h.fake.Enabled)
	}
	for _, call := range h.fake.CallLog() {
		if call == "pfctl -d" || strings.Contains(call, "-F all") {
			t.Fatalf("forbidden call %q", call)
		}
	}
	// Updates from a running core do not bring it back.
	if st, _ := c.Call(ctx, OpUpdate, &p); st.Desired.Enabled || h.loaded() != "" {
		t.Fatal("update re-enabled protection")
	}
}

func TestRestoresAfterExternalChanges(t *testing.T) {
	h := newHarness(t)
	s := h.start()
	ctx := context.Background()
	p := testPolicy()
	if _, err := h.client().Call(ctx, OpEnable, &p); err != nil {
		t.Fatal(err)
	}
	want := h.loaded()
	// Another program flushes the anchor and turns PF off.
	h.fake.SetLoaded(pf.ProtectionAnchor, "")
	h.fake.ForceDisable()
	s.mu.Lock()
	s.reconcileLocked(ctx, "verify")
	s.mu.Unlock()
	if h.loaded() != want || !h.fake.Enabled {
		t.Fatal("protection not restored")
	}
	st := s.Status(ctx)
	if st.State != sysnet.ProtectionProtected || !hasProblem(st, sysnet.ProblemModified) {
		t.Fatalf("status = %+v", st)
	}
	// Another program loads a main ruleset without Yuhaiin's anchor.
	h.fake.LoadMain([]string{`anchor "com.apple/*" all`}, nil)
	s.mu.Lock()
	s.reconcileLocked(ctx, "verify")
	s.mu.Unlock()
	if in := h.engine.Inspect(ctx); !in.FilterRef {
		t.Fatal("main ruleset reference not restored")
	}
	// It keeps doing so: after three repairs the service stops fighting
	// and reports the problem instead of claiming protection.
	for range 4 {
		h.fake.LoadMain([]string{`anchor "com.apple/*" all`}, nil)
		s.mu.Lock()
		s.reconcileLocked(ctx, "verify")
		s.mu.Unlock()
	}
	st = s.Status(ctx)
	if st.Effective || st.State == sysnet.ProtectionProtected || !hasProblem(st, sysnet.ProblemModified) {
		t.Fatalf("status = %+v", st)
	}
}

func hasProblem(st sysnet.ProtectionStatus, code string) bool {
	return slices.ContainsFunc(st.Problems, func(p sysnet.ProtectionProblem) bool { return p.Code == code })
}

func TestServiceRestartAndReboot(t *testing.T) {
	h := newHarness(t)
	h.start()
	ctx := context.Background()
	p := testPolicy()
	if _, err := h.client().Call(ctx, OpEnable, &p); err != nil {
		t.Fatal(err)
	}
	firstToken := mustState(t, h.cfg.StateFile).Token
	// The service is killed: the rules stay in the kernel.
	h.stop()
	if h.loaded() == "" {
		t.Fatal("rules removed when the service stopped")
	}
	// It starts again in the same boot: same reference, baseline rules.
	h.start()
	if tok := mustState(t, h.cfg.StateFile).Token; tok != firstToken {
		t.Fatal("reference taken again in the same boot")
	}
	if r := h.loaded(); r == "" || strings.Contains(r, "utun4") {
		t.Fatalf("after restart: %s", r)
	}
	h.stop()
	// Reboot: kernel state is empty, the boot id changes.
	h.fake.SetLoaded(pf.ProtectionAnchor, "")
	h.fake.ForceDisable()
	h.fake.LoadMain(nil, nil)
	_, _ = h.fake.Run(ctx, "", "/sbin/pfctl", "-f", h.engine.Conf)
	h.boot.Store("boot-2")
	h.start()
	st, err := h.client().Call(ctx, OpStatus, nil)
	if err != nil || st.State != sysnet.ProtectionProtected || !h.fake.Enabled || h.loaded() == "" {
		t.Fatalf("not restored at boot: %+v %v", st, err)
	}
	if s := mustState(t, h.cfg.StateFile); s.TokenBoot != "boot-2" || s.Token == firstToken {
		t.Fatalf("state = %+v", s)
	}
}

func TestStartAtBootOffWaitsForYuhaiin(t *testing.T) {
	h := newHarness(t)
	h.start()
	ctx := context.Background()
	p := testPolicy()
	p.StartAtBoot = false
	if _, err := h.client().Call(ctx, OpEnable, &p); err != nil {
		t.Fatal(err)
	}
	h.stop()
	h.fake.SetLoaded(pf.ProtectionAnchor, "")
	h.fake.ForceDisable()
	h.boot.Store("boot-2")
	h.start()
	st, _ := h.client().Call(ctx, OpStatus, nil)
	if st.State != sysnet.ProtectionInitializing || st.Effective || h.loaded() != "" || !hasProblem(st, sysnet.ProblemBootstrap) {
		t.Fatalf("status = %+v", st)
	}
	// The core connects and sends its policy: protection returns.
	if st, err := h.client().Call(ctx, OpUpdate, &p); err != nil || st.State != sysnet.ProtectionProtected {
		t.Fatalf("after update: %+v %v", st, err)
	}
}

func TestDamagedStateFailsClosed(t *testing.T) {
	h := newHarness(t)
	_ = os.MkdirAll(filepath.Dir(h.cfg.StateFile), 0o700)
	if err := os.WriteFile(h.cfg.StateFile, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.start()
	st, err := h.client().Call(context.Background(), OpStatus, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Effective || st.State != sysnet.ProtectionDegraded || !hasProblem(st, sysnet.ProblemState) {
		t.Fatalf("status = %+v", st)
	}
	r := h.loaded()
	if r == "" || strings.Contains(r, "yuhaiin_bypass") {
		t.Fatalf("not failing closed with only private networks: %s", r)
	}
	if _, err := os.Stat(h.cfg.StateFile + ".damaged"); err != nil {
		t.Fatal("damaged state not kept for inspection")
	}
}

func TestRejectedPolicyKeepsRules(t *testing.T) {
	h := newHarness(t)
	h.start()
	ctx := context.Background()
	c := h.client()
	p := testPolicy()
	if _, err := c.Call(ctx, OpEnable, &p); err != nil {
		t.Fatal(err)
	}
	before, saved := h.loaded(), mustState(t, h.cfg.StateFile)
	bad := testPolicy()
	bad.Tunnels = []protection.Tunnel{{Name: "utun4 all"}}
	st, err := c.Call(ctx, OpUpdate, &bad)
	if err == nil || h.loaded() != before || st.State != sysnet.ProtectionProtected {
		t.Fatalf("invalid policy: %v %+v", err, st)
	}
	bad = testPolicy()
	bad.BypassNetworks = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	if _, err := c.Call(ctx, OpUpdate, &bad); err == nil || h.loaded() != before {
		t.Fatal("default route accepted as bypass")
	}
	if after := mustState(t, h.cfg.StateFile); after.Policy.Fingerprint() != saved.Policy.Fingerprint() {
		t.Fatal("rejected policy saved")
	}
	// A rejected load (PF refuses the rules) keeps the previous ones too.
	h.fake.Fail["-n -a "+pf.ProtectionAnchor] = errors.New("syntax error")
	p2 := testPolicy()
	p2.BypassNetworks = append(p2.BypassNetworks, netip.MustParsePrefix("198.51.100.0/24"))
	if _, err := c.Call(ctx, OpUpdate, &p2); err == nil || h.loaded() != before {
		t.Fatal("PF rejection not reported or rules lost")
	}
}

func TestMissingPfctlIsNotProtected(t *testing.T) {
	h := newHarness(t)
	h.fake.Missing = true
	h.start()
	p := testPolicy()
	st, err := h.client().Call(context.Background(), OpEnable, &p)
	if err == nil || st.Effective || st.State == sysnet.ProtectionProtected {
		t.Fatalf("status = %+v err %v", st, err)
	}
}

func TestVanishedTunnelIsDropped(t *testing.T) {
	h := newHarness(t)
	s := h.start()
	ctx := context.Background()
	p := testPolicy()
	if _, err := h.client().Call(ctx, OpEnable, &p); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.ifaces = slices.DeleteFunc(h.ifaces, func(i iface.Info) bool { return i.Name == "utun4" })
	h.mu.Unlock()
	s.mu.Lock()
	s.reconcileLocked(ctx, "verify")
	s.mu.Unlock()
	if strings.Contains(h.loaded(), "utun4") {
		t.Fatal("rules still allow a TUN that no longer exists")
	}
}

func newRecovery(h *harness) Recovery {
	stopped := false
	return Recovery{StateFile: h.cfg.StateFile, Engine: h.engine, BootID: h.cfg.BootID, Euid: func() int { return 0 },
		StopService: func(context.Context) error { h.stop(); stopped = true; _ = stopped; return nil }}
}

func TestRecoveryWithoutService(t *testing.T) {
	h := newHarness(t)
	h.start()
	ctx := context.Background()
	p := testPolicy()
	if _, err := h.client().Call(ctx, OpEnable, &p); err != nil {
		t.Fatal(err)
	}
	other, _ := h.fake.Run(ctx, "", "/sbin/pfctl", "-E")
	h.fake.SetLoaded("org.example.vpn", "block out all\n")
	// The service hangs or crashed: recovery works without it.
	h.stop()
	var orderErr error
	h.fake.OnCall = func(call string) {
		if strings.Contains(call, "-F rules") {
			if s, _, _ := LoadState(h.cfg.StateFile); s.Enabled {
				orderErr = errors.New("rules removed before the disabled state was saved")
			}
		}
	}
	report := newRecovery(h).Run(ctx)
	h.fake.OnCall = nil
	if !report.Success || orderErr != nil {
		t.Fatalf("report = %+v %v", report, orderErr)
	}
	if h.loaded() != "" || h.fake.Loaded("org.example.vpn") == "" {
		t.Fatal("recovery did not remove only Yuhaiin's rules")
	}
	if len(h.fake.Tokens) != 1 || !strings.Contains(other, h.fake.Tokens[0]) || !h.fake.Enabled {
		t.Fatalf("other references changed: %v", h.fake.Tokens)
	}
	saved := mustState(t, h.cfg.StateFile)
	if saved.Enabled || saved.ChangedBy != "recovery" || saved.Token != "" {
		t.Fatalf("saved = %+v", saved)
	}
	// Idempotent on an empty anchor.
	if again := newRecovery(h).Run(ctx); !again.Success {
		t.Fatalf("second run = %+v", again)
	}
	// Reboot: the service starts again and keeps protection off; so does a
	// core that still sends its policy.
	h.boot.Store("boot-2")
	h.start()
	if st, _ := h.client().Call(ctx, OpUpdate, &p); st.Desired.Enabled || h.loaded() != "" {
		t.Fatal("protection came back after recovery")
	}
}

func TestRecoveryFailures(t *testing.T) {
	h := newHarness(t)
	h.start()
	ctx := context.Background()
	p := testPolicy()
	if _, err := h.client().Call(ctx, OpEnable, &p); err != nil {
		t.Fatal(err)
	}
	h.stop()
	rc := newRecovery(h)
	rc.Euid = func() int { return 501 }
	if r := rc.Run(ctx); r.Success || h.loaded() == "" {
		t.Fatal("recovery without root succeeded")
	}
	if os.Geteuid() != 0 {
		// The saved state cannot be written: recovery must not report success.
		dir := filepath.Dir(h.cfg.StateFile)
		_ = os.Chmod(dir, 0o500)
		defer func() { _ = os.Chmod(dir, 0o700) }()
		r := newRecovery(h).Run(ctx)
		if r.Success {
			t.Fatalf("success reported although the state was not saved: %+v", r)
		}
	}
	// Corrupt state: recovery still disables.
	_ = os.Chmod(filepath.Dir(h.cfg.StateFile), 0o700)
	_ = os.WriteFile(h.cfg.StateFile, []byte("garbage"), 0o600)
	if r := newRecovery(h).Run(ctx); !r.Success || mustState(t, h.cfg.StateFile).Enabled {
		t.Fatalf("corrupt state: %+v", r)
	}
}

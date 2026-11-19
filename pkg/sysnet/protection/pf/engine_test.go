package pf_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/policy"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/pf"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/pf/pftest"
)

const defaultConf = "scrub-anchor \"com.apple/*\"\nnat-anchor \"com.apple/*\"\nrdr-anchor \"com.apple/*\"\ndummynet-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\nload anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"\n"

func newEngine(t *testing.T, conf string) (*pf.Engine, *pftest.Fake) {
	dir := t.TempDir()
	f := pftest.New()
	e := &pf.Engine{Pfctl: "/sbin/pfctl", Conf: filepath.Join(dir, "pf.conf"), BackupDir: filepath.Join(dir, "state"), Anchor: pf.ProtectionAnchor, Run: f.Run}
	if conf != "" {
		if err := os.WriteFile(e.Conf, []byte(conf), 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = f.Run(context.Background(), "", "/sbin/pfctl", "-f", e.Conf)
	}
	return e, f
}

func forbidden(t *testing.T, calls []string) {
	t.Helper()
	for _, c := range calls {
		if c == "pfctl -d" || strings.Contains(c, "-F all") || (strings.Contains(c, " -F ") && !strings.Contains(c, "-a io.github.yuhaiin/")) || strings.Contains(c, " -k ") {
			t.Fatalf("forbidden global PF call %q", c)
		}
	}
}

func TestEnsureRegisteredEditsAndReloads(t *testing.T) {
	ctx := context.Background()
	e, f := newEngine(t, defaultConf)
	changed, err := e.EnsureRegistered(ctx, true)
	if err != nil || !changed {
		t.Fatalf("changed %v err %v", changed, err)
	}
	data, _ := os.ReadFile(e.Conf)
	if reg := pf.Registered(string(data)); !reg.Filter || !reg.NAT || !reg.Managed {
		t.Fatalf("pf.conf = %s", data)
	}
	backup, err := os.ReadFile(filepath.Join(e.BackupDir, "pf.conf.previous"))
	if err != nil || string(backup) != defaultConf {
		t.Fatalf("backup = %q %v", backup, err)
	}
	in := e.Inspect(ctx)
	if !in.FilterRef || !in.NATRef {
		t.Fatalf("running ruleset not reloaded: %+v", in)
	}
	calls := f.CallLog()
	// Validated before the edit and before the reload.
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "pfctl -n -f "+e.Conf) || !strings.Contains(joined, "pfctl -n -f "+e.BackupDir) {
		t.Fatalf("no dry runs:\n%s", joined)
	}
	forbidden(t, calls)
	// Second run: nothing to do.
	n := len(f.CallLog())
	if changed, err := e.EnsureRegistered(ctx, true); err != nil || changed {
		t.Fatal(changed, err)
	}
	for _, c := range f.CallLog()[n:] {
		if strings.HasPrefix(c, "pfctl -f") {
			t.Fatal("reloaded although registered")
		}
	}
}

func TestEnsureRegisteredRefusesBrokenConf(t *testing.T) {
	ctx := context.Background()
	e, _ := newEngine(t, "INVALID line\n")
	if _, err := e.EnsureRegistered(ctx, true); err == nil {
		t.Fatal("edited a broken pf.conf")
	}
	data, _ := os.ReadFile(e.Conf)
	if string(data) != "INVALID line\n" {
		t.Fatal("broken pf.conf was changed")
	}
}

func TestEnsureRegisteredRestoresOnReloadFailure(t *testing.T) {
	ctx := context.Background()
	e, f := newEngine(t, defaultConf)
	f.Fail["pfctl -f "+e.Conf] = errors.New("exit status 1")
	if _, err := e.EnsureRegistered(ctx, true); err == nil {
		t.Fatal("failure not reported")
	}
	data, _ := os.ReadFile(e.Conf)
	if string(data) != defaultConf {
		t.Fatalf("pf.conf not restored:\n%s", data)
	}
	var problem *protection.ProblemError
	if _, err := e.EnsureRegistered(ctx, true); !errors.As(err, &problem) || problem.Problem.Code != sysnet.ProblemRegistration {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadValidatesFirstAndFlushIsScoped(t *testing.T) {
	ctx := context.Background()
	e, f := newEngine(t, defaultConf)
	rs, err := pf.Compile(protection.Policy{Mode: sysnet.ProtectionModeStandard, PrivateNetworks: policy.PrivateNetworks()}, pf.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Load(ctx, rs); err != nil {
		t.Fatal(err)
	}
	if pf.LoadedID(e.Inspect(ctx).Rules) != rs.ID {
		t.Fatal("not loaded")
	}
	// A rejected ruleset leaves the loaded one.
	bad := pf.Ruleset{Text: "INVALID\n", ID: "x"}
	if err := e.Load(ctx, bad); err == nil {
		t.Fatal("invalid ruleset loaded")
	}
	if pf.LoadedID(e.Inspect(ctx).Rules) != rs.ID {
		t.Fatal("previous rules lost after a rejected load")
	}
	// Other anchors survive a flush.
	f.SetLoaded("com.apple/250.ApplicationFirewall", "block in all\n")
	if err := e.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if f.Loaded(pf.ProtectionAnchor) != "" || f.Loaded("com.apple/250.ApplicationFirewall") == "" {
		t.Fatal("flush not scoped to Yuhaiin's anchor")
	}
	forbidden(t, f.CallLog())
}

func TestReferences(t *testing.T) {
	ctx := context.Background()
	e, f := newEngine(t, defaultConf)
	other, _ := f.Run(ctx, "", "/sbin/pfctl", "-E")
	token, err := e.Acquire(ctx)
	if err != nil || token == "" {
		t.Fatal(token, err)
	}
	if err := e.Release(ctx, token); err != nil {
		t.Fatal(err)
	}
	if in := e.Inspect(ctx); !in.Enabled || len(in.Tokens) != 1 || !strings.Contains(other, in.Tokens[0]) {
		t.Fatalf("other program's reference affected: %+v", in)
	}
	if err := e.Release(ctx, "1; pfctl -d"); err == nil {
		t.Fatal("non-numeric token accepted")
	}
	forbidden(t, f.CallLog())
}

func TestMissingPfctl(t *testing.T) {
	e, f := newEngine(t, defaultConf)
	f.Missing = true
	_, err := e.Acquire(context.Background())
	var problem *protection.ProblemError
	if !errors.As(err, &problem) || problem.Problem.Code != sysnet.ProblemEnableFailed {
		t.Fatalf("err = %v", err)
	}
	in := e.Inspect(context.Background())
	if in.EnabledKnown || in.RulesKnown || len(in.Errors) == 0 {
		t.Fatalf("unknown state reported as known: %+v", in)
	}
}

func TestUnregisterRemovesOnlyManagedLines(t *testing.T) {
	ctx := context.Background()
	e, _ := newEngine(t, defaultConf)
	if _, err := e.EnsureRegistered(ctx, true); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(e.Conf)
	_ = os.WriteFile(e.Conf, append(data, []byte("anchor \"org.example\"\n")...), 0o644)
	if changed, err := e.Unregister(ctx); err != nil || !changed {
		t.Fatal(changed, err)
	}
	data, _ = os.ReadFile(e.Conf)
	if string(data) != defaultConf+"anchor \"org.example\"\n" {
		t.Fatalf("pf.conf = %s", data)
	}
	if in := e.Inspect(ctx); in.FilterRef || in.NATRef {
		t.Fatal("running ruleset still references the anchor")
	}
}

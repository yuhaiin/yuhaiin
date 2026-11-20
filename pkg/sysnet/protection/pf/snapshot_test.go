package pf_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/policy"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/pf"
)

func TestSnapshotMarksYuhaiinAndKeepsCounters(t *testing.T) {
	ctx := context.Background()
	e, f := newEngine(t, defaultConf)
	if _, err := e.EnsureRegistered(ctx, true); err != nil {
		t.Fatal(err)
	}
	p := protection.Policy{Mode: sysnet.ProtectionModeStandard, PrivateNetworks: policy.PrivateNetworks(),
		BypassNetworks: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, Tunnels: []protection.Tunnel{{Name: "utun4", IPv4: true}}, OwnTraffic: true}
	rs, err := pf.Compile(p, pf.Env{OwnGroup: 340})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Load(ctx, rs); err != nil {
		t.Fatal(err)
	}
	f.Blocked = 7
	f.SetLoaded(pf.ForwardAnchor, "nat on en0 inet from 192.168.20.0/24 to any -> (en0)\npass in quick on en1 inet from 192.168.20.0/24 to any keep state\n")
	calls := len(f.CallLog())
	snap := e.Snapshot(ctx)
	if !snap.Available || snap.Backend != "pf" || len(snap.Errors) != 0 {
		t.Fatalf("snapshot = %+v", snap)
	}
	// Read-only: only "-s" and "-T show" calls.
	for _, c := range f.CallLog()[calls:] {
		if !strings.Contains(c, " -s ") && !strings.HasSuffix(c, "-T show") {
			t.Fatalf("snapshot changed something: %q", c)
		}
	}
	// The whole main ruleset, Yuhaiin's lines marked.
	var marked, other int
	for _, m := range snap.Main {
		if m.Yuhaiin {
			marked++
			if !strings.Contains(m.Text, "io.github.yuhaiin/*") {
				t.Errorf("marked line %q", m.Text)
			}
		} else {
			other++
		}
	}
	if marked != 2 || other == 0 {
		t.Fatalf("main = %+v", snap.Main)
	}
	if snap.Main[0].Kind != "translation" {
		t.Fatalf("translation rules are not first: %+v", snap.Main[0])
	}
	prot, fwd := snap.Rulesets[0], snap.Rulesets[1]
	if prot.Name != pf.ProtectionAnchor || fwd.Name != pf.ForwardAnchor || len(prot.Rules) != rs.Rules || len(fwd.Rules) != 2 {
		t.Fatalf("rulesets = %+v", snap.Rulesets)
	}
	categories := map[string]int{}
	for _, r := range prot.Rules {
		categories[r.Category]++
		if !r.Counters {
			t.Errorf("no counters for %q", r.Text)
		}
	}
	for _, c := range []string{sysnet.RuleLoopback, sysnet.RulePrivate, sysnet.RuleLocal, sysnet.RuleBypass, sysnet.RuleTunnel, sysnet.RuleOwn, sysnet.RuleBlock} {
		if categories[c] == 0 {
			t.Errorf("no %s rule in %v", c, categories)
		}
	}
	last := prot.Rules[len(prot.Rules)-1]
	if last.Category != sysnet.RuleBlock || last.Packets != 7 {
		t.Fatalf("block rule = %+v", last)
	}
	if fwd.Rules[0].Category != sysnet.RuleForward {
		t.Fatal("forwarding rules not marked")
	}
	tables := map[string]sysnet.ProtectionRuleTable{}
	for _, tb := range prot.Tables {
		tables[tb.Name] = tb
	}
	if tables["yuhaiin_private"].Count != len(policy.PrivateNetworks()) || tables["yuhaiin_bypass"].Entries[0] != "203.0.113.0/24" {
		t.Fatalf("tables = %+v", prot.Tables)
	}
	if !snap.Config.Registered || len(snap.Config.Lines) != 2 || !snap.Config.Lines[0].Managed || snap.Config.Lines[0].Number == 0 {
		t.Fatalf("config = %+v", snap.Config)
	}
	for _, want := range []string{"### pfctl -s rules", "### pfctl -a io.github.yuhaiin/protection -v -s rules", "yuhaiin_private"} {
		if !strings.Contains(snap.Raw, want) {
			t.Errorf("raw lacks %q", want)
		}
	}
}

func TestSnapshotWithoutPfctl(t *testing.T) {
	e, f := newEngine(t, defaultConf)
	f.Missing = true
	snap := e.Snapshot(context.Background())
	if snap.Available || snap.Reason == "" || len(snap.Errors) == 0 {
		t.Fatalf("snapshot = %+v", snap)
	}
}

func TestCategoryOfUnknownLabels(t *testing.T) {
	if pf.Category("") != sysnet.RuleOther || pf.Category("someone-else") != sysnet.RuleOther {
		t.Fatal("foreign rule categorized as Yuhaiin's")
	}
}

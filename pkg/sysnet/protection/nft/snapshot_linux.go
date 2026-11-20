//go:build linux && !android

package nft

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/policy"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/helper"
)

func defaultPrivate() []netip.Prefix { return policy.PrivateNetworks() }

// MaxSetEntries bounds the addresses returned per set.
const MaxSetEntries = 2000

// Snapshot reads, without changing anything, every base chain of the system
// (in evaluation order per hook, Yuhaiin's marked), Yuhaiin's table with its
// rule counters and sets, and the boot unit. plan, the policy Yuhaiin last
// compiled, supplies the rule text when it matches what is loaded.
func Snapshot(ctx context.Context, plan Plan) sysnet.ProtectionRules {
	out := sysnet.ProtectionRules{Backend: "nftables", ReadAt: time.Now().Unix(), Rulesets: []sysnet.ProtectionRuleset{}, Main: []sysnet.ProtectionMainRule{}}
	chains, err := Chains()
	if err != nil {
		out.Errors = append(out.Errors, err.Error())
	}
	for _, c := range chains {
		text := fmt.Sprintf("%s %s %s: hook %s priority %d", c.Family, c.Table, c.Name, c.Hook, c.Priority)
		if c.Policy != "" {
			text += " policy " + c.Policy
		}
		out.Main = append(out.Main, sysnet.ProtectionMainRule{Kind: "chain", Text: text, Yuhaiin: c.Yuhaiin})
	}
	in := Inspect()
	if in.Err != nil {
		out.Errors = append(out.Errors, in.Err.Error())
	}
	set := sysnet.ProtectionRuleset{Name: "inet " + Table, Purpose: "protection", Rules: []sysnet.ProtectionRule{}}
	matches := plan.ID != "" && LoadedID(labels(in)) == plan.ID && len(plan.Rules) == len(in.Rules)
	for i, r := range in.Rules {
		text := fmt.Sprintf("comment %q", r.Label)
		if matches {
			text = plan.Rules[i].String()
		}
		set.Rules = append(set.Rules, sysnet.ProtectionRule{Text: text, Label: r.Label, Category: Category(r.Label), Counters: true, Packets: r.Packets, Bytes: r.Bytes})
	}
	for _, s := range plan.Sets {
		entries, ok := in.Sets[s.Name]
		if !ok {
			continue
		}
		t := sysnet.ProtectionRuleTable{Name: s.Name, Count: len(entries), Entries: entries}
		if len(entries) > MaxSetEntries {
			t.Entries, t.Truncated = entries[:MaxSetEntries], true
		}
		set.Tables = append(set.Tables, t)
	}
	out.Rulesets = append(out.Rulesets, set)

	out.Config.Path = UnitPath
	if data, err := os.ReadFile(UnitPath); err == nil {
		out.Config.Registered = bootUnitEnabled(ctx)
		out.Config.Lines = []sysnet.ProtectionConfigLine{}
		for i, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "ExecStart=") || strings.HasPrefix(line, "Before=") || strings.HasPrefix(line, "WantedBy=") {
				out.Config.Lines = append(out.Config.Lines, sysnet.ProtectionConfigLine{Number: i + 1, Text: line, Managed: true})
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		out.Config.Error = err.Error()
	} else {
		out.Config.Lines = []sysnet.ProtectionConfigLine{}
	}

	var raw strings.Builder
	if nft, err := exec.LookPath("nft"); err == nil {
		// Read-only listings, for copying into bug reports.
		for _, args := range [][]string{{"list", "table", "inet", Table}, {"list", "ruleset"}} {
			c, cancel := context.WithTimeout(ctx, 10*time.Second)
			text, _ := exec.CommandContext(c, nft, args...).CombinedOutput()
			cancel()
			fmt.Fprintf(&raw, "### nft %s\n%s\n", strings.Join(args, " "), strings.TrimRight(string(text), "\n"))
		}
	} else {
		raw.WriteString("### inet " + Table + " (nft is not installed; rendered by Yuhaiin)\n" + plan.Text())
	}
	out.Raw = raw.String()
	out.Available = in.Known || err == nil
	if !out.Available {
		out.Reason = "nftables could not be read"
		if os.Geteuid() != 0 {
			out.Reason += "; Yuhaiin is not running as root"
		}
	}
	return out
}

// Recover removes Network Protection without the Yuhaiin core: the disabled
// state is saved first, then the boot unit is disabled and the table
// removed, and both are checked again.
func Recover(ctx context.Context) helper.RecoveryReport {
	var report helper.RecoveryReport
	step := func(name string, err error, detail string) bool {
		s := helper.RecoveryStep{Name: name, OK: err == nil, Detail: detail}
		if err != nil {
			s.Detail = err.Error()
		}
		report.Steps = append(report.Steps, s)
		return err == nil
	}
	if os.Geteuid() != 0 {
		step("administrator rights", helper.ErrNotRoot, "")
		return report
	}
	step("administrator rights", nil, "running as root")
	ok := true
	state, exists, loadErr := helper.LoadState(StateFile)
	in := Inspect()
	if !exists && !in.Exists {
		step("Yuhaiin protection present", nil, "no saved state and no protection table; nothing to remove")
		report.Success = true
		return report
	}
	step("Yuhaiin protection present", nil, fmt.Sprintf("saved state: %v, table loaded: %v", exists, in.Exists))
	if loadErr != nil {
		_ = os.Rename(StateFile, StateFile+".damaged")
		state = helper.State{}
	}
	state.Enabled, state.ChangedBy, state.UpdatedAt = false, "recovery", time.Now().Unix()
	ok = step("save disabled state", helper.SaveState(StateFile, state), "protection will not be restored at the next startup") && ok
	ok = step("disable the startup unit", setBootUnit(ctx, false), UnitName) && ok
	ok = step("remove protection rules", Remove(), "only the inet "+Table+" table was deleted") && ok
	after := Inspect()
	var verify error
	switch {
	case !after.Known:
		verify = errors.Join(errors.New("cannot read nftables"), after.Err)
	case after.Exists:
		verify = errors.New("the protection table still exists")
	}
	ok = step("verify protection rules removed", verify, "") && ok
	saved, _, err := helper.LoadState(StateFile)
	if err == nil && saved.Enabled {
		err = errors.New("the saved state still requests protection")
	}
	ok = step("verify disabled at next startup", err, "") && ok
	report.Success = ok
	return report
}

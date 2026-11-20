package pf

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
)

// MaxTableEntries bounds the addresses returned per table; Count keeps the
// real number.
const MaxTableEntries = 2000

// Snapshot reads, without changing anything, Yuhaiin's rule sets (kill
// switch and forwarding) with counters and tables, the main ruleset with
// Yuhaiin's lines marked, and Yuhaiin's lines in pf.conf. Every call is a
// fixed, read-only pfctl invocation ("-s", "-T show").
func (e *Engine) Snapshot(ctx context.Context) sysnet.ProtectionRules {
	out := sysnet.ProtectionRules{Backend: "pf", ReadAt: time.Now().Unix(), Rulesets: []sysnet.ProtectionRuleset{}, Main: []sysnet.ProtectionMainRule{}}
	var raw strings.Builder
	section := func(title, text string) {
		fmt.Fprintf(&raw, "### %s\n%s\n", title, strings.TrimRight(stripWarnings(text), "\n"))
	}
	read := func(args ...string) (string, bool) {
		text, err := e.pfctl(ctx, "", args...)
		if err != nil {
			out.Errors = append(out.Errors, err.Error())
			return "", false
		}
		return text, true
	}

	ok := false
	for _, main := range []struct{ kind, what string }{{"translation", "nat"}, {"filter", "rules"}} {
		text, good := read("-s", main.what)
		if !good {
			continue
		}
		ok = true
		section("pfctl -s "+main.what, text)
		for _, r := range ParseRules(text) {
			out.Main = append(out.Main, sysnet.ProtectionMainRule{Kind: main.kind, Text: r.Text, Yuhaiin: strings.Contains(r.Text, `"`+Anchor+`/`) || strings.Contains(r.Text, `"`+Anchor+`"`)})
		}
	}

	for _, rs := range []struct{ name, purpose string }{{ProtectionAnchor, "protection"}, {ForwardAnchor, "forward"}} {
		set := sysnet.ProtectionRuleset{Name: rs.name, Purpose: rs.purpose, Rules: []sysnet.ProtectionRule{}}
		var errs []string
		for _, what := range []string{"nat", "rules"} {
			if rs.purpose == "protection" && what == "nat" {
				continue
			}
			text, err := e.pfctl(ctx, "", "-a", rs.name, "-v", "-s", what)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			ok = true
			section(fmt.Sprintf("pfctl -a %s -v -s %s", rs.name, what), text)
			for _, r := range ParseRules(text) {
				category := Category(r.Label)
				if rs.purpose == "forward" {
					category = sysnet.RuleForward
				}
				set.Rules = append(set.Rules, sysnet.ProtectionRule{Text: r.Text, Label: r.Label, Category: category, Counters: r.HasPackets,
					Evaluations: r.Evaluations, Packets: r.Packets, Bytes: r.Bytes, States: r.States})
			}
		}
		if names, err := e.pfctl(ctx, "", "-a", rs.name, "-s", "Tables"); err == nil {
			for _, name := range tableNames(names) {
				entries, err := e.pfctl(ctx, "", "-a", rs.name, "-t", name, "-T", "show")
				if err != nil {
					errs = append(errs, err.Error())
					continue
				}
				section(fmt.Sprintf("pfctl -a %s -t %s -T show", rs.name, name), entries)
				set.Tables = append(set.Tables, tableOf(name, entries))
			}
		}
		set.Error = strings.Join(errs, "; ")
		out.Rulesets = append(out.Rulesets, set)
	}

	out.Config.Path = e.Conf
	if data, err := os.ReadFile(e.Conf); err != nil {
		out.Config.Error = err.Error()
	} else {
		out.Config.Registered = Registered(string(data)).Filter
		out.Config.Lines = []sysnet.ProtectionConfigLine{}
		for i, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, Anchor) {
				out.Config.Lines = append(out.Config.Lines, sysnet.ProtectionConfigLine{Number: i + 1, Text: line, Managed: strings.Contains(line, confMarker)})
			}
		}
	}

	out.Available = ok
	if !ok {
		out.Reason = "The packet filter could not be read"
		if os.Geteuid() != 0 {
			out.Reason += "; Yuhaiin is not running as root"
		}
	}
	out.Raw = raw.String()
	return out
}

// stripWarnings drops the ALTQ notices pfctl prints before its output.
func stripWarnings(text string) string {
	var b strings.Builder
	for line := range strings.SplitSeq(text, "\n") {
		if strings.Contains(line, "ALTQ") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// tableNames parses "pfctl -s Tables": one name per line, possibly with
// flags in front ("--a-r-- yuhaiin_private").
func tableNames(text string) []string {
	var names []string
	for line := range strings.SplitSeq(stripWarnings(text), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[len(fields)-1]
		if strings.HasPrefix(name, "yuhaiin_") {
			names = append(names, name)
		}
	}
	return names
}

func tableOf(name, text string) sysnet.ProtectionRuleTable {
	t := sysnet.ProtectionRuleTable{Name: name, Entries: []string{}}
	for line := range strings.SplitSeq(stripWarnings(text), "\n") {
		entry := strings.TrimSpace(line)
		if entry == "" {
			continue
		}
		t.Count++
		if len(t.Entries) < MaxTableEntries {
			t.Entries = append(t.Entries, entry)
		}
	}
	t.Truncated = len(t.Entries) < t.Count
	return t
}

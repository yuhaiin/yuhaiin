// Package pf implements Network Protection with the macOS packet filter.
//
// All of Yuhaiin's PF rules live below one anchor, io.github.yuhaiin. The
// main ruleset (/etc/pf.conf) evaluates it through one managed line per rule
// type, placed before every other filter rule. The kill switch is the child
// anchor io.github.yuhaiin/protection; forwarding uses
// io.github.yuhaiin/forward.
//
// The rules let allowed traffic pass without "quick" and tag it, and end
// with one quick block of untagged outgoing traffic:
//
//	pass out ... tag io.github.yuhaiin.pass        loopback, private, bypass, TUN, Yuhaiin
//	block return out quick ! tagged io.github.yuhaiin.pass
//
// So blocked traffic is final (no later rule of another program can pass
// it), while traffic Yuhaiin allows still goes through every later rule, and
// another firewall's block keeps working.
//
// This file is pure: it renders rules and parses pfctl output, so it is
// tested on every platform. Running pfctl is in engine.go.
package pf

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
)

const (
	// Anchor is the root of every Yuhaiin PF rule.
	Anchor = "io.github.yuhaiin"
	// ProtectionAnchor holds the kill switch rules.
	ProtectionAnchor = Anchor + "/protection"
	// ForwardAnchor holds the forwarding (side router) rules.
	ForwardAnchor = Anchor + "/forward"

	passTag = "io.github.yuhaiin.pass"
	// Labels identify Yuhaiin's rules in pfctl output. The block label
	// carries the policy fingerprint, so a loaded ruleset can be matched to
	// the policy it was generated from.
	labelPrefix = "yuhaiin-"
	blockLabel  = labelPrefix + "block-"
	ownLabel    = labelPrefix + "own-"
	tunLabel    = labelPrefix + "tunnel"

	tablePrivate = "yuhaiin_private"
	tableBypass  = "yuhaiin_bypass"
)

// Darwin interface names: lower-case letters followed by a unit number.
var interfaceName = regexp.MustCompile(`^[a-z]{1,10}[0-9]{1,4}$`)

// ValidInterface reports whether name is a macOS interface name. Names are
// never quoted into rules unless they pass.
func ValidInterface(name string) error {
	if !interfaceName.MatchString(name) {
		return fmt.Errorf("invalid interface name %q", name)
	}
	return nil
}

// Env is what the compiled rules need besides the policy.
type Env struct {
	// OwnGroup is the numeric group of the Yuhaiin process's sockets; 0
	// means Yuhaiin's own traffic is not allowed.
	OwnGroup int
}

// Ruleset is a compiled policy.
type Ruleset struct {
	Text string
	// ID is the fingerprint embedded in the block rule's label.
	ID string
	// Rules is the number of filter rules, for verification.
	Rules int
}

func prefixList(list []netip.Prefix) string {
	parts := make([]string, len(list))
	for i, p := range list {
		if p.IsSingleIP() {
			parts[i] = p.Addr().String()
		} else {
			parts[i] = p.String()
		}
	}
	return strings.Join(parts, ", ")
}

// Compile renders the protection rules for policy. Every value comes from
// validated, typed input (prefixes, names checked by ValidInterface, a
// numeric group), never from free text, so input cannot inject rules.
func Compile(p protection.Policy, env Env) (Ruleset, error) {
	if err := p.Validate(); err != nil {
		return Ruleset{}, err
	}
	p = p.Normalize()
	for _, t := range p.Tunnels {
		if err := ValidInterface(t.Name); err != nil {
			return Ruleset{}, fmt.Errorf("tunnel: %w", err)
		}
		if t.Name == "lo0" {
			return Ruleset{}, fmt.Errorf("tunnel: loopback is not a tunnel")
		}
	}
	if env.OwnGroup < 0 || env.OwnGroup > 1<<31-1 {
		return Ruleset{}, fmt.Errorf("invalid socket group %d", env.OwnGroup)
	}
	sum := sha256.Sum256([]byte(p.Fingerprint() + fmt.Sprintf("/%d/%v", env.OwnGroup, p.OwnTraffic)))
	id := hex.EncodeToString(sum[:])[:16]

	var tables, rules []string
	pass := func(rule, label string) {
		rules = append(rules, fmt.Sprintf("pass out %s tag %s label %q", rule, passTag, labelPrefix+label))
	}
	if len(p.PrivateNetworks) > 0 {
		tables = append(tables, fmt.Sprintf("table <%s> const { %s }", tablePrivate, prefixList(p.PrivateNetworks)))
	}
	if len(p.BypassNetworks) > 0 {
		tables = append(tables, fmt.Sprintf("table <%s> const { %s }", tableBypass, prefixList(p.BypassNetworks)))
	}

	pass("on lo0 all", "loopback")
	if len(p.PrivateNetworks) > 0 {
		pass(fmt.Sprintf("to <%s>", tablePrivate), "private")
	}
	// Link-scoped services the network itself needs. Multicast beyond the
	// link (224.0.0.0/4, ff00::/8) and other special ranges stay blocked.
	pass("inet to { 224.0.0.0/24, 255.255.255.255 }", "link-multicast")
	pass("inet6 to ff02::/16", "link-multicast6")
	pass("inet proto udp from any port 68 to any port 67", "dhcp")
	pass("inet6 proto udp from any port 546 to any port 547", "dhcp6")
	pass("inet6 proto icmp6 all icmp6-type { routersol, neighbrsol, neighbradv }", "nd")
	if len(p.BypassNetworks) > 0 {
		pass(fmt.Sprintf("to <%s>", tableBypass), "bypass")
	}
	for _, t := range p.Tunnels {
		// if-bound: a state created on the TUN never matches packets that
		// leave through another interface after the TUN is gone.
		pass(fmt.Sprintf("on %s all keep state (if-bound)", t.Name), "tunnel")
	}
	if p.OwnTraffic && env.OwnGroup > 0 {
		// "flags any" keeps connections Yuhaiin opened before the rules
		// were loaded; the socket owner is checked for every new state.
		pass(fmt.Sprintf("proto tcp all group %d flags any keep state", env.OwnGroup), "own-tcp")
		pass(fmt.Sprintf("proto udp all group %d keep state", env.OwnGroup), "own-udp")
	}
	rules = append(rules, fmt.Sprintf("block return out quick all ! tagged %s label %q", passTag, blockLabel+id))

	var b strings.Builder
	fmt.Fprintf(&b, "# Yuhaiin Network Protection %s. Generated; do not edit.\n", id)
	for _, t := range tables {
		b.WriteString(t)
		b.WriteByte('\n')
	}
	for _, r := range rules {
		b.WriteString(r)
		b.WriteByte('\n')
	}
	return Ruleset{Text: b.String(), ID: id, Rules: len(rules)}, nil
}

// RuleCounters are the counters pfctl -v prints under a rule.
type RuleCounters struct {
	Label                  string
	Evaluations            uint64
	Packets, Bytes, States uint64
	HasPackets, HasStates  bool
}

var (
	labelRE    = regexp.MustCompile(`label "([^"]*)"`)
	counterRE  = regexp.MustCompile(`(Evaluations|Packets|Bytes|States):\s*(\d+)`)
	tokenRE    = regexp.MustCompile(`Token\s*:\s*(\d+)`)
	statusRE   = regexp.MustCompile(`(?m)^Status:\s*(Enabled|Disabled)`)
	numberOnly = regexp.MustCompile(`^\d+$`)
)

var ruleKeywords = map[string]bool{"pass": true, "block": true, "match": true, "anchor": true, "scrub": true, "antispoof": true,
	"nat": true, "rdr": true, "binat": true, "no": true, "dummynet": true}

// ParseRules parses "pfctl -v -s rules": each rule line is followed by
// indented "[ Evaluations: ... ]" lines.
func ParseRules(out string) []RuleCounters {
	var rules []RuleCounters
	for line := range strings.SplitSeq(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			if len(rules) == 0 {
				continue
			}
			r := &rules[len(rules)-1]
			for _, m := range counterRE.FindAllStringSubmatch(trimmed, -1) {
				v, _ := strconv.ParseUint(m[2], 10, 64)
				switch m[1] {
				case "Evaluations":
					r.Evaluations = v
				case "Packets":
					r.Packets, r.HasPackets = v, true
				case "Bytes":
					r.Bytes = v
				case "States":
					r.States, r.HasStates = v, true
				}
			}
			continue
		}
		if keyword, _, _ := strings.Cut(trimmed, " "); !ruleKeywords[keyword] {
			// pfctl mixes warnings ("No ALTQ support in kernel") into
			// its output; they are not rules.
			continue
		}
		rc := RuleCounters{}
		if m := labelRE.FindStringSubmatch(trimmed); m != nil {
			rc.Label = m[1]
		}
		rules = append(rules, rc)
	}
	return rules
}

// LoadedID returns the policy ID of the loaded protection ruleset, or "".
func LoadedID(rules []RuleCounters) string {
	for _, r := range rules {
		if id, ok := strings.CutPrefix(r.Label, blockLabel); ok {
			return id
		}
	}
	return ""
}

// Summary aggregates the counters of a loaded protection ruleset.
type Summary struct {
	Rules        int
	Blocked      RuleCounters
	HasBlock     bool
	OwnStates    uint64
	HasOwnStates bool
	TunnelRules  int
}

func Summarize(rules []RuleCounters) Summary {
	var s Summary
	s.Rules = len(rules)
	for _, r := range rules {
		switch {
		case strings.HasPrefix(r.Label, blockLabel):
			s.Blocked, s.HasBlock = r, true
		case strings.HasPrefix(r.Label, ownLabel):
			s.OwnStates += r.States
			s.HasOwnStates = s.HasOwnStates || r.HasStates
		case r.Label == tunLabel:
			s.TunnelRules++
		}
	}
	return s
}

// ParseEnabled parses "pfctl -s info". ok is false when the output has no
// status line.
func ParseEnabled(out string) (enabled, ok bool) {
	m := statusRE.FindStringSubmatch(out)
	if m == nil {
		return false, false
	}
	return m[1] == "Enabled", true
}

// ParseToken returns the reference token printed by "pfctl -E".
func ParseToken(out string) string {
	if m := tokenRE.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

// ParseReferences returns the enable reference tokens listed by
// "pfctl -s References". Lines without a numeric token are ignored, so
// header lines and unknown formats yield no tokens rather than wrong ones.
func ParseReferences(out string) []string {
	var tokens []string
	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.FieldsSeq(line)
		for f := range fields {
			// Tokens are large numbers; PIDs and timestamps are short.
			if numberOnly.MatchString(f) && len(f) >= 8 {
				tokens = append(tokens, f)
			}
		}
	}
	slices.SortFunc(tokens, cmp.Compare)
	return slices.Compact(tokens)
}

// MainReferences reports whether the main ruleset printed by "pfctl -s rules"
// (or "-s nat") evaluates Yuhaiin's anchors.
func MainReferences(out, keyword string) bool {
	want := keyword + ` "` + Anchor + `/*"`
	for line := range strings.SplitSeq(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), want) {
			return true
		}
	}
	return false
}

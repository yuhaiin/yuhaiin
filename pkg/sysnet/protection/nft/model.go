// Package nft implements Network Protection on Linux with nftables.
//
// All rules live in one table, inet yuhaiin_protection, with one output
// chain. The chain accepts allowed traffic and ends with a reject:
//
//	oifname "lo" accept                           loopback
//	ip  daddr @private4 accept / ip6 daddr @private6 accept
//	link-local multicast, broadcast, DHCP, IPv6 neighbor discovery
//	ip  daddr @bypass4  accept / ip6 daddr @bypass6  accept
//	oif <index> accept                            each running Yuhaiin TUN
//	meta mark 0x500 accept                        Yuhaiin's own sockets
//	reject                                        everything else
//
// nftables evaluates every base chain of a hook: an accept only ends this
// chain, while a drop or reject in any chain is final. So the kill switch
// cannot be bypassed by another table's accept, and another firewall's drop
// still applies to traffic Yuhaiin allows.
//
// TUNs are matched by interface index, which the kernel does not reuse for a
// new interface: when Yuhaiin exits its TUN disappears and the rule matches
// nothing, so another program's TUN of the same name never passes. The
// socket mark can only be set with CAP_NET_ADMIN.
//
// This file is pure (rule model and rendering) and tested everywhere; the
// netlink part is in table_linux.go.
package nft

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
	"go4.org/netipx"
)

const (
	// Table is the only nftables table this package creates or deletes.
	Table = "yuhaiin_protection"
	Chain = "output"

	labelPrefix = "yuhaiin-"
	blockLabel  = labelPrefix + "block-"
)

// Tunnel is a Yuhaiin TUN resolved to its current interface index.
type Tunnel struct {
	Name  string
	Index int
}

// Env is what the rules need besides the policy.
type Env struct {
	Tunnels []Tunnel
	// OwnMark is the socket mark of Yuhaiin's own sockets; 0 disables the
	// rule.
	OwnMark uint32
}

// Set is a named interval set of addresses of one family.
type Set struct {
	Name   string
	V6     bool
	Ranges []netipx.IPRange
}

// Rule is one rule of the output chain.
type Rule struct {
	Label   string
	Family  string // "ip", "ip6" or "" for both
	OifName string
	Oif     int
	Set     string // destination address set
	Daddr   netip.Prefix
	L4      string // "tcp", "udp", "icmpv6" or ""
	Sport   uint16
	Dport   uint16
	// ICMPType is the ICMPv6 type, 0 for none.
	ICMPType uint8
	Mark     uint32
	// NotL4 matches everything but L4 (the reject of non-TCP traffic).
	NotL4   bool
	Verdict string // "accept" or "reject"
	// RejectTCPReset rejects with a TCP reset instead of ICMP.
	RejectTCPReset bool
}

// Plan is a compiled policy.
type Plan struct {
	ID    string
	Sets  []Set
	Rules []Rule
}

// Category classifies one of Yuhaiin's rules by its label.
func Category(label string) string {
	switch {
	case label == labelPrefix+"loopback":
		return sysnet.RuleLoopback
	case label == labelPrefix+"private":
		return sysnet.RulePrivate
	case label == labelPrefix+"bypass":
		return sysnet.RuleBypass
	case label == labelPrefix+"tunnel":
		return sysnet.RuleTunnel
	case label == labelPrefix+"own":
		return sysnet.RuleOwn
	case strings.HasPrefix(label, blockLabel):
		return sysnet.RuleBlock
	case strings.HasPrefix(label, labelPrefix+"link-multicast"), strings.HasPrefix(label, labelPrefix+"dhcp"), label == labelPrefix+"nd":
		return sysnet.RuleLocal
	}
	return sysnet.RuleOther
}

// LoadedID returns the policy id carried by the block rule's label.
func LoadedID(labels []string) string {
	for _, l := range labels {
		if id, ok := strings.CutPrefix(l, blockLabel); ok {
			return id
		}
	}
	return ""
}

func ranges(list []netip.Prefix, v6 bool) []netipx.IPRange {
	var b netipx.IPSetBuilder
	for _, p := range list {
		if p.Addr().Is6() == v6 {
			b.AddPrefix(p)
		}
	}
	set, _ := b.IPSet()
	if set == nil {
		return nil
	}
	return set.Ranges()
}

// Compile renders the protection rules for policy. All values are typed
// (prefixes, interface indexes, numbers), so input cannot inject rules.
func Compile(p protection.Policy, env Env) (Plan, error) {
	if err := p.Validate(); err != nil {
		return Plan{}, err
	}
	p = p.Normalize()
	for _, t := range env.Tunnels {
		if t.Index <= 0 {
			return Plan{}, fmt.Errorf("tunnel %q has no interface index", t.Name)
		}
		if t.Name == "lo" {
			return Plan{}, fmt.Errorf("tunnel: loopback is not a tunnel")
		}
	}
	key := p.Fingerprint() + fmt.Sprintf("/%d/%v", env.OwnMark, p.OwnTraffic)
	for _, t := range env.Tunnels {
		key += fmt.Sprintf("/%s=%d", t.Name, t.Index)
	}
	sum := sha256.Sum256([]byte(key))
	plan := Plan{ID: hex.EncodeToString(sum[:])[:16]}

	addSets := func(base string, list []netip.Prefix) (v4, v6 bool) {
		if r := ranges(list, false); len(r) > 0 {
			plan.Sets = append(plan.Sets, Set{Name: base + "4", Ranges: r})
			v4 = true
		}
		if r := ranges(list, true); len(r) > 0 {
			plan.Sets = append(plan.Sets, Set{Name: base + "6", V6: true, Ranges: r})
			v6 = true
		}
		return
	}
	accept := func(r Rule) { r.Verdict = "accept"; plan.Rules = append(plan.Rules, r) }

	accept(Rule{Label: labelPrefix + "loopback", OifName: "lo"})
	if v4, v6 := addSets("private", p.PrivateNetworks); v4 || v6 {
		if v4 {
			accept(Rule{Label: labelPrefix + "private", Family: "ip", Set: "private4"})
		}
		if v6 {
			accept(Rule{Label: labelPrefix + "private", Family: "ip6", Set: "private6"})
		}
	}
	accept(Rule{Label: labelPrefix + "link-multicast", Family: "ip", Daddr: netip.MustParsePrefix("224.0.0.0/24")})
	accept(Rule{Label: labelPrefix + "link-multicast", Family: "ip", Daddr: netip.MustParsePrefix("255.255.255.255/32")})
	accept(Rule{Label: labelPrefix + "link-multicast6", Family: "ip6", Daddr: netip.MustParsePrefix("ff02::/16")})
	accept(Rule{Label: labelPrefix + "dhcp", Family: "ip", L4: "udp", Sport: 68, Dport: 67})
	accept(Rule{Label: labelPrefix + "dhcp6", Family: "ip6", L4: "udp", Sport: 546, Dport: 547})
	for _, typ := range []uint8{133, 135, 136} { // router solicitation, neighbor solicitation / advertisement
		accept(Rule{Label: labelPrefix + "nd", Family: "ip6", L4: "icmpv6", ICMPType: typ})
	}
	if v4, v6 := addSets("bypass", p.BypassNetworks); v4 || v6 {
		if v4 {
			accept(Rule{Label: labelPrefix + "bypass", Family: "ip", Set: "bypass4"})
		}
		if v6 {
			accept(Rule{Label: labelPrefix + "bypass", Family: "ip6", Set: "bypass6"})
		}
	}
	for _, t := range env.Tunnels {
		accept(Rule{Label: labelPrefix + "tunnel", Oif: t.Index})
	}
	if p.OwnTraffic && env.OwnMark != 0 {
		accept(Rule{Label: labelPrefix + "own", Mark: env.OwnMark})
	}
	plan.Rules = append(plan.Rules,
		Rule{Label: blockLabel + plan.ID, L4: "tcp", Verdict: "reject", RejectTCPReset: true},
		Rule{Label: blockLabel + plan.ID, L4: "tcp", NotL4: true, Verdict: "reject"},
	)
	return plan, nil
}

// String renders a rule in nft syntax, for display and tests.
func (r Rule) String() string {
	var parts []string
	if r.OifName != "" {
		parts = append(parts, fmt.Sprintf("oifname %q", r.OifName))
	}
	if r.Oif != 0 {
		parts = append(parts, fmt.Sprintf("oif %d", r.Oif))
	}
	addr := "ip"
	if r.Family == "ip6" {
		addr = "ip6"
	}
	if r.Set != "" {
		parts = append(parts, fmt.Sprintf("%s daddr @%s", addr, r.Set))
	}
	if r.Daddr.IsValid() {
		parts = append(parts, fmt.Sprintf("%s daddr %s", addr, r.Daddr))
	}
	switch {
	case r.L4 == "icmpv6":
		parts = append(parts, fmt.Sprintf("icmpv6 type %d", r.ICMPType))
	case r.NotL4:
		parts = append(parts, "meta l4proto != "+r.L4)
	case r.L4 != "" && (r.Sport != 0 || r.Dport != 0):
		parts = append(parts, fmt.Sprintf("%s sport %d %s dport %d", r.L4, r.Sport, r.L4, r.Dport))
	case r.L4 != "":
		parts = append(parts, "meta l4proto "+r.L4)
	}
	if r.Mark != 0 {
		parts = append(parts, fmt.Sprintf("meta mark %#x", r.Mark))
	}
	parts = append(parts, "counter")
	switch {
	case r.Verdict == "reject" && r.RejectTCPReset:
		parts = append(parts, "reject with tcp reset")
	case r.Verdict == "reject":
		parts = append(parts, "reject with icmpx admin-prohibited")
	default:
		parts = append(parts, r.Verdict)
	}
	parts = append(parts, fmt.Sprintf("comment %q", r.Label))
	return strings.Join(parts, " ")
}

// Text renders the whole table in nft syntax.
func (p Plan) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", Table)
	for _, s := range p.Sets {
		typ := "ipv4_addr"
		if s.V6 {
			typ = "ipv6_addr"
		}
		elems := make([]string, len(s.Ranges))
		for i, r := range s.Ranges {
			if pfx, ok := r.Prefix(); ok {
				elems[i] = pfx.String()
			} else {
				elems[i] = r.String()
			}
		}
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype %s\n\t\tflags interval\n\t\telements = { %s }\n\t}\n", s.Name, typ, strings.Join(elems, ", "))
	}
	fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook output priority filter; policy accept;\n", Chain)
	for _, r := range p.Rules {
		fmt.Fprintf(&b, "\t\t%s\n", r)
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

// rangeString renders [from, toExclusive) as a prefix when it is one.
func rangeString(from, toExclusive []byte) string {
	f, ok1 := netip.AddrFromSlice(from)
	t, ok2 := netip.AddrFromSlice(toExclusive)
	if !ok1 || !ok2 {
		return fmt.Sprintf("%v-%v", from, toExclusive)
	}
	r := netipx.IPRangeFrom(f.Unmap(), t.Unmap().Prev())
	if p, ok := r.Prefix(); ok {
		return p.String()
	}
	return r.String()
}

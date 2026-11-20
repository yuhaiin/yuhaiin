// Package wfp implements Network Protection on Windows with the Windows
// Filtering Platform.
//
// Yuhaiin registers one provider and one sublayer with the highest weight.
// In it, a block filter catches every outgoing connection (ALE connect
// layers, IPv4 and IPv6) and higher-weighted permit filters let through
// loopback, private networks, link-local services, bypass routes, Yuhaiin's
// TUN (by interface LUID) and Yuhaiin's own executable (by application ID).
//
// WFP arbitration makes a block in any sublayer final, while Yuhaiin's
// permits are soft: another firewall can still block what Yuhaiin allows.
//
// The baseline filters are persistent when protection starts at boot: the
// Base Filtering Engine applies them at boot, before services start. The
// TUN and application permits are added in a dynamic session owned by the
// Yuhaiin process, so Windows removes them as soon as the process exits.
//
// This file is pure (rule model, stable IDs) and tested everywhere.
package wfp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
)

const (
	labelPrefix = "yuhaiin-"
	blockLabel  = labelPrefix + "block"
	// maxPrefixesPerFilter bounds the OR-ed address conditions of one filter.
	maxPrefixesPerFilter = 1000
)

// Weights inside Yuhaiin's sublayer: permits win over the block.
const (
	weightBlock   = 0
	weightPermit  = 10
	weightRuntime = 12
)

// Condition is one match of a filter. Conditions of the same kind are
// OR-ed by WFP, different kinds AND-ed.
type Condition struct {
	Kind   string // loopback, remote, udp, icmp6, app, interface
	Prefix netip.Prefix
	Local  uint16
	Remote uint16
	App    string
	LUID   uint64
}

// Filter is one WFP filter.
type Filter struct {
	Label      string
	V6         bool
	Permit     bool
	Weight     uint64
	Conditions []Condition
	// Runtime filters belong to the running Yuhaiin process.
	Runtime    bool
	Persistent bool
}

// Tunnel is a Yuhaiin TUN resolved to its interface LUID.
type Tunnel struct {
	Name string
	LUID uint64
}

// Env is what the filters need besides the policy.
type Env struct {
	// App is the path of Yuhaiin's executable ("" disables its permit).
	App     string
	Tunnels []Tunnel
}

// Plan is a compiled policy.
type Plan struct {
	ID      string
	Filters []Filter
}

// Key identifies a filter by everything that defines it, so an unchanged
// filter keeps its ID across updates and a changed one gets a new ID.
func (f Filter) Key() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s|v6=%v|permit=%v|w=%d|rt=%v|p=%v", f.Label, f.V6, f.Permit, f.Weight, f.Runtime, f.Persistent)
	for _, c := range f.Conditions {
		fmt.Fprintf(&b, "|%s:%s:%d:%d:%s:%d", c.Kind, c.Prefix, c.Local, c.Remote, c.App, c.LUID)
	}
	return b.String()
}

// GUID derives the filter's stable 128-bit ID (RFC 4122 version 5 layout).
func (f Filter) GUID() [16]byte {
	sum := sha256.Sum256([]byte("io.github.yuhaiin/wfp/" + f.Key()))
	var g [16]byte
	copy(g[:], sum[:16])
	g[6] = g[6]&0x0f | 0x50
	g[8] = g[8]&0x3f | 0x80
	return g
}

// String describes a filter for display.
func (f Filter) String() string {
	action := "block"
	if f.Permit {
		action = "permit"
	}
	family := "IPv4"
	if f.V6 {
		family = "IPv6"
	}
	parts := []string{fmt.Sprintf("%s outbound %s", action, family)}
	for _, c := range f.Conditions {
		switch c.Kind {
		case "loopback":
			parts = append(parts, "loopback")
		case "remote":
			parts = append(parts, "to "+c.Prefix.String())
		case "udp":
			parts = append(parts, fmt.Sprintf("udp %d->%d", c.Local, c.Remote))
		case "icmp6":
			parts = append(parts, fmt.Sprintf("icmpv6 type %d", c.Local))
		case "app":
			parts = append(parts, "app "+c.App)
		case "interface":
			parts = append(parts, fmt.Sprintf("interface luid %#x", c.LUID))
		}
	}
	if f.Runtime {
		parts = append(parts, "(while Yuhaiin runs)")
	}
	return strings.Join(parts, " ")
}

// Category classifies a filter by its label.
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
	case label == blockLabel:
		return sysnet.RuleBlock
	case strings.HasPrefix(label, labelPrefix+"link-multicast"), strings.HasPrefix(label, labelPrefix+"dhcp"), label == labelPrefix+"nd":
		return sysnet.RuleLocal
	}
	return sysnet.RuleOther
}

func remoteFilters(label string, list []netip.Prefix, persistent bool) []Filter {
	var out []Filter
	for _, v6 := range []bool{false, true} {
		var conds []Condition
		flush := func() {
			if len(conds) > 0 {
				out = append(out, Filter{Label: label, V6: v6, Permit: true, Weight: weightPermit, Conditions: conds, Persistent: persistent})
				conds = nil
			}
		}
		for _, p := range list {
			if p.Addr().Is6() != v6 {
				continue
			}
			conds = append(conds, Condition{Kind: "remote", Prefix: p})
			if len(conds) == maxPrefixesPerFilter {
				flush()
			}
		}
		flush()
	}
	return out
}

// Compile renders the filters for policy. persistent makes the baseline
// survive a reboot (protection at startup).
func Compile(p protection.Policy, env Env) (Plan, error) {
	if err := p.Validate(); err != nil {
		return Plan{}, err
	}
	p = p.Normalize()
	for _, t := range env.Tunnels {
		if t.LUID == 0 {
			return Plan{}, fmt.Errorf("tunnel %q has no interface LUID", t.Name)
		}
	}
	persistent := p.StartAtBoot
	var fs []Filter
	both := func(f Filter) {
		f.Persistent = persistent && !f.Runtime
		v4, v6 := f, f
		v6.V6 = true
		fs = append(fs, v4, v6)
	}
	both(Filter{Label: labelPrefix + "loopback", Permit: true, Weight: weightPermit, Conditions: []Condition{{Kind: "loopback"}}})
	fs = append(fs, remoteFilters(labelPrefix+"private", p.PrivateNetworks, persistent)...)
	fs = append(fs, remoteFilters(labelPrefix+"link-multicast", []netip.Prefix{
		netip.MustParsePrefix("224.0.0.0/24"), netip.MustParsePrefix("255.255.255.255/32"), netip.MustParsePrefix("ff02::/16")}, persistent)...)
	fs = append(fs,
		Filter{Label: labelPrefix + "dhcp", Permit: true, Weight: weightPermit, Persistent: persistent, Conditions: []Condition{{Kind: "udp", Local: 68, Remote: 67}}},
		Filter{Label: labelPrefix + "dhcp6", V6: true, Permit: true, Weight: weightPermit, Persistent: persistent, Conditions: []Condition{{Kind: "udp", Local: 546, Remote: 547}}},
	)
	for _, typ := range []uint16{133, 135, 136} {
		fs = append(fs, Filter{Label: labelPrefix + "nd", V6: true, Permit: true, Weight: weightPermit, Persistent: persistent, Conditions: []Condition{{Kind: "icmp6", Local: typ}}})
	}
	fs = append(fs, remoteFilters(labelPrefix+"bypass", p.BypassNetworks, persistent)...)
	for _, t := range env.Tunnels {
		both(Filter{Label: labelPrefix + "tunnel", Permit: true, Weight: weightRuntime, Runtime: true, Conditions: []Condition{{Kind: "interface", LUID: t.LUID}}})
	}
	if p.OwnTraffic && env.App != "" {
		both(Filter{Label: labelPrefix + "own", Permit: true, Weight: weightRuntime, Runtime: true, Conditions: []Condition{{Kind: "app", App: env.App}}})
	}
	both(Filter{Label: blockLabel, Weight: weightBlock})

	var key strings.Builder
	for _, f := range fs {
		key.WriteString(f.Key())
		key.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(key.String()))
	return Plan{ID: hex.EncodeToString(sum[:])[:16], Filters: fs}, nil
}

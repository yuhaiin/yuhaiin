package sysnet

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/policy"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
	"go4.org/netipx"
)

// SetProtection connects Network Protection. f receives the protection
// inputs after every reconciliation (configuration saves, TUN changes,
// network changes, GeoIP updates) and once now.
func (m *Manager) SetProtection(f func(protection.Inputs)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.protect = f
	if f != nil && m.protectInputs != nil {
		f(*m.protectInputs)
	}
}

// protectionInputs derives the kill switch inputs from the effective
// routing state, never from the OS routing table, so a physical default
// route can never become a bypass:
//
//   - bypass CIDRs of enabled rules that send traffic to a Yuhaiin TUN,
//     and the countries a GeoIP-inverted rule keeps direct;
//   - the destinations an active rule routes to another interface, as
//     assigned after priorities (custom rules only: a global or
//     non_private rule to an interface would mean "the whole Internet
//     outside Yuhaiin" and is reported instead).
//
// Private networks are allowed separately and default routes never.
func (m *Manager) protectionInputs(assignments []policy.Assignment, infos []candidateInfo, statusByID map[string]*sysnet.RuleStatus) protection.Inputs {
	var b netipx.IPSetBuilder
	var ignored []string
	for _, rule := range m.config.Routes {
		if !rule.Enabled || rule.Target.Type != sysnet.TargetTunInbound {
			continue
		}
		bypass, _ := sysnet.ParseCIDRs("bypass", rule.Match.BypassCIDRs)
		for _, p := range bypass {
			if p.Bits() == 0 {
				// A 0.0.0.0/0 or ::/0 bypass would switch protection off,
				// also after private networks are subtracted from it.
				ignored = append(ignored, fmt.Sprintf("Rule %q: the bypass %s covers the whole Internet and is ignored", rule.Name, p))
				continue
			}
			b.AddPrefix(p)
		}
		if rule.Match.Mode == sysnet.ModeCustom && rule.Match.GeoIPInvert && len(rule.Match.GeoIPCountries) != 0 {
			countries, _ := sysnet.NormalizeCountries(rule.Match.GeoIPCountries)
			if m.opts.GeoIP == nil {
				ignored = append(ignored, fmt.Sprintf("Rule %q: the GeoIP database is not available, so the countries it keeps direct are blocked", rule.Name))
				continue
			}
			prefixes, err := m.opts.GeoIP.PrefixesByCountries(countries)
			if err != nil {
				ignored = append(ignored, fmt.Sprintf("Rule %q: %v; the countries it keeps direct are blocked", rule.Name, err))
				continue
			}
			for _, p := range prefixes {
				b.AddPrefix(p)
			}
		}
	}
	for i, a := range assignments {
		info := infos[i]
		if info.rule == nil || info.rule.Target.Type != sysnet.TargetInterface || a.Set == nil {
			continue
		}
		if rs := statusByID[info.rule.ID]; rs == nil || (rs.State != sysnet.StateActive && rs.State != sysnet.StateDegraded && rs.State != sysnet.StateConflict) {
			continue
		}
		if info.rule.Match.Mode != sysnet.ModeCustom {
			ignored = append(ignored, fmt.Sprintf("Rule %q routes the whole Internet to %s; the kill switch does not treat it as a bypass", info.rule.Name, info.target.name))
			continue
		}
		b.AddSet(a.Set)
	}
	for _, p := range policy.PrivateNetworks() {
		b.RemovePrefix(p)
	}
	set, _ := b.IPSet()
	var bypass []netip.Prefix
	if set != nil {
		bypass = set.Prefixes()
	}
	in := protection.Inputs{Bypass: bypass, Ignored: ignored}
	ids := make([]string, 0, len(m.tuns))
	for id := range m.tuns {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		tun := m.tuns[id]
		if tun.Platform != nil || tun.Interface == "" {
			continue
		}
		in.Tunnels = append(in.Tunnels, protection.Tunnel{Name: tun.Interface, IPv4: tun.IPv4, IPv6: tun.IPv6})
	}
	return in
}

func (m *Manager) publishProtection(in protection.Inputs) {
	m.protectInputs = &in
	if m.protect != nil {
		m.protect(in)
	}
}

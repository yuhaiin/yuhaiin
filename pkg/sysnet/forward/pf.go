package forward

import (
	"fmt"
	"net/netip"
	"strings"
)

// PFAnchor is the only PF anchor this package loads or flushes. The default
// macOS /etc/pf.conf evaluates every child of com.apple ("nat-anchor" and
// "anchor com.apple/*"), so no global PF configuration is changed.
const PFAnchor = "com.apple/yuhaiin"

// NextHop returns the route-to next hop of a point-to-point egress without a
// gateway: like macOS routes through a utun, its own address of the family.
type NextHop func(link int, v6 bool) (netip.Addr, error)

func pfFamily(v6 bool) string {
	if v6 {
		return "inet6"
	}
	return "inet"
}

func pfSources(s []netip.Prefix) string {
	if len(s) == 1 {
		return s[0].String()
	}
	parts := make([]string, len(s))
	for i, p := range s {
		parts[i] = p.String()
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

// CompilePF renders a plan as rules of the Yuhaiin PF anchor. Translation
// rules come first, as PF requires; filter rules use "quick", so the first
// match wins in configuration order:
//
//	nat on EGRESS FAMILY from SOURCES to any -> (EGRESS)           masquerade
//	pass in quick on INGRESS FAMILY from SOURCES to self            this host itself
//	pass in quick on INGRESS route-to (EGRESS NEXTHOP) ... to DEST  selected egress
//	pass in quick on INGRESS FAMILY from SOURCES                    everything else, routing table
//	pass in quick on INGRESS FAMILY to MULTICAST/BROADCAST          link-local services
//	block in quick on INGRESS FAMILY to ! self                      other devices are not forwarded
//
// TProxy interception is not available on macOS.
func CompilePF(plan Plan, nextHop NextHop) (string, error) {
	var nat, filter, fallback []string
	ingresses := []string{}
	families := map[string]bool{}
	for _, rule := range plan.Rules {
		if rule.Egress.tproxy() {
			return "", fmt.Errorf("rule %s: TProxy interception is not supported on macOS", rule.ID)
		}
		seen := false
		for _, in := range ingresses {
			seen = seen || in == rule.Ingress
		}
		if !seen {
			ingresses = append(ingresses, rule.Ingress)
		}
		for _, v6 := range []bool{false, true} {
			if (v6 && !plan.IPv6) || (!v6 && !plan.IPv4) {
				continue
			}
			sources := rule.sources(v6)
			if len(sources) == 0 {
				continue
			}
			family := pfFamily(v6)
			families[family] = true
			from := "from " + pfSources(sources)
			filter = append(filter, fmt.Sprintf("pass in quick on %s %s %s to self keep state", rule.Ingress, family, from))
			if !rule.Egress.Routes {
				gw := rule.Egress.Gateway
				if v6 {
					gw = rule.Egress.GatewayV6
				}
				if !gw.IsValid() {
					var err error
					if gw, err = nextHop(rule.Egress.Link, v6); err != nil {
						return "", fmt.Errorf("rule %s: %w", rule.ID, err)
					}
				}
				to := "to any"
				if dsts := split(rule.Destinations, v6); len(dsts) != 0 {
					to = "to " + pfSources(dsts)
				}
				filter = append(filter, fmt.Sprintf("pass in quick on %s route-to (%s %s) %s %s %s keep state", rule.Ingress, rule.Egress.Name, gw, family, from, to))
				if rule.Masquerade {
					nat = append(nat, fmt.Sprintf("nat on %s %s %s to any -> (%s)", rule.Egress.Name, family, from, rule.Egress.Name))
				}
			}
			fallback = append(fallback, fmt.Sprintf("pass in quick on %s %s %s keep state", rule.Ingress, family, from))
		}
	}
	if len(families) == 0 {
		return "", nil
	}
	lines := append(append([]string{}, nat...), filter...)
	lines = append(lines, fallback...)
	for _, in := range ingresses {
		if families["inet"] {
			lines = append(lines, fmt.Sprintf("pass in quick on %s inet to { 224.0.0.0/4, 255.255.255.255 }", in),
				fmt.Sprintf("block in quick on %s inet to ! self", in))
		}
		if families["inet6"] {
			lines = append(lines, fmt.Sprintf("pass in quick on %s inet6 to { ff00::/8, fe80::/10 }", in),
				fmt.Sprintf("block in quick on %s inet6 to ! self", in))
		}
	}
	return strings.Join(lines, "\n") + "\n", nil
}

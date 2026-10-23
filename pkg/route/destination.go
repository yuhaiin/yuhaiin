package route

import (
	"context"
	"net/netip"
	"strings"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type destinationMatcher struct {
	domains  []string
	prefixes []netip.Prefix
}

func newDestinationMatcher(expr contract.DestinationExpr) *destinationMatcher {
	m := new(destinationMatcher)
	for _, domain := range expr.Domains {
		m.domains = append(m.domains, strings.ToLower(strings.TrimSuffix(domain, ".")))
	}
	for _, cidr := range expr.CIDRs {
		if prefix, err := contract.DestinationPrefix(cidr); err == nil {
			m.prefixes = append(m.prefixes, prefix)
		}
	}
	return m
}

func (m *destinationMatcher) Match(ctx context.Context, resolved netapi.Address) bool {
	original := netapi.PolicyOriginalDestination(ctx)
	if original == nil {
		original = resolved
	}
	matched := false
	if original.IsFqdn() {
		host := strings.TrimSuffix(original.Hostname(), ".")
		for _, domain := range m.domains {
			if suffix, ok := strings.CutPrefix(domain, "*."); ok {
				if len(host) > len(suffix)+1 && host[len(host)-len(suffix)-1] == '.' && strings.EqualFold(host[len(host)-len(suffix):], suffix) {
					matched = true
					break
				}
			} else if strings.EqualFold(host, domain) {
				matched = true
				break
			}
		}
	}
	if !matched && !resolved.IsFqdn() {
		ip := resolved.(netapi.IPAddress).AddrPort().Addr().Unmap()
		for _, prefix := range m.prefixes {
			if prefix.Contains(ip) {
				matched = true
				break
			}
		}
	}
	if store := netapi.GetContext(ctx); store.RecordingMatchHistory() {
		store.AddConditionHistory("destination", original.Hostname(), "Destination", matched)
	}
	return matched
}

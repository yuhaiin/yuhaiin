package route

import (
	"fmt"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
)

// buildMatchTraceTemplate is called once when preparing a routing snapshot.
// No per-connection recursive node trees or duplicated labels are retained.
func buildMatchTraceTemplate(m Matcher) *contractconnection.MatchTraceTemplate {
	if degraded, ok := m.(threeValuedMatcher); ok {
		m = degraded.matcher
	}
	kind, label, children := matcherShape(m)
	template := &contractconnection.MatchTraceTemplate{
		Type: kind, Label: label,
	}
	if kind == "condition" {
		switch v := m.(type) {
		case constantMatcher:
			template.Constant = fmt.Sprintf("%t", bool(v))
		case *Network:
			switch v.network {
			case "tcp", "udp", "network_tcp", "network_udp":
				template.EmitsHistory = true
			default:
				template.Constant = "false"
			}
		default:
			template.EmitsHistory = true
		}
	}
	for _, child := range children {
		template.Children = append(template.Children, *buildMatchTraceTemplate(child))
	}
	return template
}

func matcherShape(m Matcher) (string, string, []Matcher) {
	switch v := m.(type) {
	case *And:
		return "and", "AND", v.matchers
	case *Or:
		return "or", "OR", v.matchers
	case notMatcher:
		return "not", "NOT", []Matcher{v.child}
	case List:
		return "condition", string(v), nil
	case unavailableListMatcher:
		return "condition", string(v), nil
	case incompleteListMatcher:
		return "condition", string(v), nil
	case constantMatcher:
		return "condition", fmt.Sprintf("Constant %t", bool(v)), nil
	case *Inbound:
		return "condition", "Inbound", nil
	case *Network:
		return "condition", "Network", nil
	case *Port:
		return "condition", "Port", nil
	case *Geoip:
		return "condition", "GeoIP", nil
	default:
		return "condition", "Condition", nil
	}
}

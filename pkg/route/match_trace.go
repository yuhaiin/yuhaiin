package route

import (
	"context"
	"fmt"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// traceRuleMatch records the matcher actually evaluated, including three-valued
// degraded rules. The trace is produced during evaluation, not reconstructed
// from the flat list history (which loses NOT and short-circuit information).
func traceRuleMatch(ctx context.Context, addr netapi.Address, matcher Matcher) (bool, contractconnection.MatchTrace) {
	if degraded, ok := matcher.(threeValuedMatcher); ok {
		matcher = degraded.matcher
	}
	result, trace := traceEvaluate(ctx, addr, matcher)
	return result == matchTrue, trace
}

func traceState(value matchValue) string {
	switch value {
	case matchTrue:
		return "hit"
	case matchUnknown:
		return "unknown"
	default:
		return "miss"
	}
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

func skippedMatchTrace(m Matcher) contractconnection.MatchTrace {
	kind, label, children := matcherShape(m)
	node := contractconnection.MatchTrace{Type: kind, Label: label, State: "skipped"}
	for _, child := range children {
		node.Children = append(node.Children, skippedMatchTrace(child))
	}
	return node
}

func traceEvaluate(ctx context.Context, addr netapi.Address, m Matcher) (matchValue, contractconnection.MatchTrace) {
	kind, label, children := matcherShape(m)
	node := contractconnection.MatchTrace{Type: kind, Label: label}
	var result matchValue
	switch kind {
	case "and":
		result = matchTrue
		unknown := false
		for _, child := range children {
			if result == matchFalse {
				node.Children = append(node.Children, skippedMatchTrace(child))
				continue
			}
			v, childTrace := traceEvaluate(ctx, addr, child)
			node.Children = append(node.Children, childTrace)
			if v == matchFalse {
				result = matchFalse
			} else if v == matchUnknown {
				unknown = true
			}
		}
		if result != matchFalse && unknown {
			result = matchUnknown
		}
	case "or":
		result = matchFalse
		unknown := false
		for _, child := range children {
			if result == matchTrue {
				node.Children = append(node.Children, skippedMatchTrace(child))
				continue
			}
			v, childTrace := traceEvaluate(ctx, addr, child)
			node.Children = append(node.Children, childTrace)
			if v == matchTrue {
				result = matchTrue
			} else if v == matchUnknown {
				unknown = true
			}
		}
		if result != matchTrue && unknown {
			result = matchUnknown
		}
	case "not":
		result = matchFalse
		if len(children) > 0 {
			v, childTrace := traceEvaluate(ctx, addr, children[0])
			node.Children = []contractconnection.MatchTrace{childTrace}
			switch v {
			case matchTrue:
				result = matchFalse
			case matchFalse:
				result = matchTrue
			default:
				result = matchUnknown
			}
		}
	default:
		store := netapi.GetContext(ctx)
		before := 0
		history := store.MatchHistory()
		if len(history) > 0 {
			before = len(history[len(history)-1].History)
		}
		switch m.(type) {
		case unavailableListMatcher, incompleteListMatcher:
			result = evaluateMatch(m, ctx, addr)
		default:
			if m.Match(ctx, addr) {
				result = matchTrue
			} else {
				result = matchFalse
			}
		}
		history = store.MatchHistory()
		if len(history) > 0 && len(history[len(history)-1].History) > before {
			leaf := history[len(history)-1].History[len(history[len(history)-1].History)-1]
			if leaf.ListName != "" {
				node.Label = leaf.ListName
			}
			node.Kind = leaf.Kind
			node.ID = leaf.ID
		}
	}
	node.State = traceState(result)
	return result, node
}

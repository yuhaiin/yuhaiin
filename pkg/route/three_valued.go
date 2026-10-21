package route

import (
	"context"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// matchValue uses strong Kleene three-valued logic: an unavailable list is
// unknown, not false. In particular, NOT unknown must not become true.
type matchValue uint8

const (
	matchFalse matchValue = iota
	matchTrue
	matchUnknown
)

type unavailableListMatcher string

func (m unavailableListMatcher) Match(ctx context.Context, _ netapi.Address) bool {
	store := netapi.GetContext(ctx)
	id := string(m)
	store.AddConditionHistory("list-unavailable", id, store.ConnOptions().ListName(id), false)
	return false
}

// An incomplete list can prove a positive match from its loaded sources,
// but a miss is UNKNOWN because another source could have matched.
type incompleteListMatcher string

func (m incompleteListMatcher) Match(ctx context.Context, addr netapi.Address) bool {
	return List(m).Match(ctx, addr)
}

type threeValuedMatcher struct{ matcher Matcher }

func (m threeValuedMatcher) Match(ctx context.Context, addr netapi.Address) bool {
	return evaluateMatch(m.matcher, ctx, addr) == matchTrue
}

// evaluateMatch short-circuits only after a definitive answer. If one branch
// is unknown, a later true OR branch or false AND branch can still decide.
func evaluateMatch(m Matcher, ctx context.Context, addr netapi.Address) matchValue {
	switch matcher := m.(type) {
	case unavailableListMatcher:
		matcher.Match(ctx, addr)
		return matchUnknown
	case incompleteListMatcher:
		if matcher.Match(ctx, addr) {
			return matchTrue
		}
		return matchUnknown
	case *And:
		unknown := false
		for _, child := range matcher.matchers {
			switch evaluateMatch(child, ctx, addr) {
			case matchFalse:
				return matchFalse
			case matchUnknown:
				unknown = true
			}
		}
		if unknown {
			return matchUnknown
		}
		return matchTrue
	case *Or:
		unknown := false
		for _, child := range matcher.matchers {
			switch evaluateMatch(child, ctx, addr) {
			case matchTrue:
				return matchTrue
			case matchUnknown:
				unknown = true
			}
		}
		if unknown {
			return matchUnknown
		}
		return matchFalse
	case notMatcher:
		switch evaluateMatch(matcher.child, ctx, addr) {
		case matchTrue:
			return matchFalse
		case matchFalse:
			return matchTrue
		default:
			return matchUnknown
		}
	default:
		if matcher.Match(ctx, addr) {
			return matchTrue
		}
		return matchFalse
	}
}

// possibleKnownMatch conservatively checks whether an expression can ever
// resolve to a definite true/false using the remaining healthy conditions.
// Leaves other than constant and unavailable lists may yield either result.
func possibleKnownMatch(m Matcher) (canTrue, canFalse bool) {
	switch matcher := m.(type) {
	case unavailableListMatcher:
		return false, false
	case incompleteListMatcher:
		return true, false
	case constantMatcher:
		return bool(matcher), !bool(matcher)
	case *And:
		canTrue = true
		for _, child := range matcher.matchers {
			ct, cf := possibleKnownMatch(child)
			canTrue = canTrue && ct
			canFalse = canFalse || cf
		}
		return canTrue, canFalse
	case *Or:
		canFalse = true
		for _, child := range matcher.matchers {
			ct, cf := possibleKnownMatch(child)
			canTrue = canTrue || ct
			canFalse = canFalse && cf
		}
		return canTrue, canFalse
	case notMatcher:
		ct, cf := possibleKnownMatch(matcher.child)
		return cf, ct
	default:
		return true, true
	}
}

func parseMatcherWithUnavailable(rule contractroute.RouteRule, unavailable, incomplete map[string]bool) Matcher {
	children := make([]Matcher, 0, len(rule.Rules))
	for _, expr := range rule.Rules {
		children = append(children, parseConditionWithDegraded(expr, unavailable, incomplete))
	}
	return NewOr(rule.Name, children...)
}

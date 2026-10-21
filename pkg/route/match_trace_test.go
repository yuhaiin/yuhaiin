package route

import (
	"testing"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestTraceRuleMatchNestedShortCircuit(t *testing.T) {
	ctx := netapi.WithContext(t.Context())
	ctx.NewRuleMatch("test", "test")
	matcher := NewAnd(
		NewOr("", constantMatcher(false), constantMatcher(true), constantMatcher(true)),
		notMatcher{constantMatcher(false)},
		NewOr("", constantMatcher(false), constantMatcher(false)),
		constantMatcher(true),
	)
	matched, trace := traceRuleMatch(ctx, nil, matcher)
	if matched || trace.State != "miss" || trace.Type != "and" {
		t.Fatalf("unexpected result: matched=%v trace=%+v", matched, trace)
	}
	if len(trace.Children) != 4 {
		t.Fatalf("children: %+v", trace.Children)
	}
	if trace.Children[0].State != "hit" || trace.Children[0].Children[2].State != "skipped" {
		t.Fatalf("OR did not short-circuit: %+v", trace.Children[0])
	}
	if trace.Children[1].State != "hit" || trace.Children[1].Children[0].State != "miss" {
		t.Fatalf("NOT did not invert: %+v", trace.Children[1])
	}
	if trace.Children[3].State != "skipped" {
		t.Fatalf("AND did not short-circuit: %+v", trace.Children[3])
	}
}

func TestTraceDegradedNotUnknown(t *testing.T) {
	ctx := netapi.WithContext(t.Context())
	ctx.NewRuleMatch("test", "test")
	matcher := threeValuedMatcher{notMatcher{unavailableListMatcher("missing")}}
	matched, trace := traceRuleMatch(ctx, nil, matcher)
	if matched || trace.State != "unknown" || trace.Children[0].State != "unknown" {
		t.Fatalf("NOT unknown must remain unknown: matched=%v trace=%+v", matched, trace)
	}
}

func TestTraceKeepsRuleExpressionSemantics(t *testing.T) {
	rule := contractroute.RouteRule{Name: "nested", Rules: []contractroute.RuleExpr{
		{Type:"not",Not:&contractroute.RuleExpr{Type:"always"}},
		{Type:"always"},
	}}
	ctx := netapi.WithContext(t.Context())
	ctx.NewRuleMatch("r", "nested")
	matched, trace := traceRuleMatch(ctx, nil, ParseMatcher(rule))
	if !matched || trace.Type != "or" || trace.Children[0].State != "miss" || trace.Children[1].State != "hit" {
		t.Fatalf("unexpected %+v, matched %v", trace, matched)
	}
}

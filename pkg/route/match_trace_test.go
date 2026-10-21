package route

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

func TestTraceTemplateMirrorsCompiledMatcher(t *testing.T) {
	matcher := NewAnd(
		NewOr("", constantMatcher(false), constantMatcher(true), constantMatcher(true)),
		notMatcher{constantMatcher(false)},
		NewOr("", constantMatcher(false), constantMatcher(false)),
		constantMatcher(true),
	)
	template := buildMatchTraceTemplate(matcher)
	if template.Type != "and" || len(template.Children) != 4 || template.Children[0].Type != "or" {
		t.Fatalf("unexpected template: %+v", template)
	}
	trace := contractconnection.ReconstructMatchTrace(template, nil)
	if trace.State != "miss" || trace.Children[0].State != "hit" ||
		trace.Children[0].Children[2].State != "skipped" ||
		trace.Children[1].State != "hit" || trace.Children[3].State != "skipped" {
		t.Fatalf("invalid replay: %+v", trace)
	}
}

func TestTraceTemplatePreservesRuleOrder(t *testing.T) {
	rule := contractroute.RouteRule{Name: "nested", Rules: []contractroute.RuleExpr{
		{Type: "not", Not: &contractroute.RuleExpr{Type: "always"}},
		{Type: "always"},
	}}
	template := buildMatchTraceTemplate(ParseMatcher(rule))
	trace := contractconnection.ReconstructMatchTrace(template, nil)
	if trace.State != "hit" || trace.Type != "or" ||
		trace.Children[0].State != "miss" || trace.Children[1].State != "hit" {
		t.Fatalf("unexpected trace: %+v", trace)
	}
}

func TestTraceTemplateUnknownNotInversion(t *testing.T) {
	template := buildMatchTraceTemplate(threeValuedMatcher{notMatcher{unavailableListMatcher("missing")}})
	trace := contractconnection.ReconstructMatchTrace(template, []contractconnection.MatchResult{
		{Kind: "list-unavailable", ID: "missing", ListName: "Missing", Matched: false},
	})
	if trace.State != "unknown" || trace.Children[0].State != "unknown" {
		t.Fatalf("unknown must not match under NOT: %+v", trace)
	}
}


// Verify the replayed graph matches the *real* matcher execution, rather
// than relying solely on synthetic leaf outcomes in the contract tests.
func TestTraceReplayMatchesRealShortCircuitEvaluation(t *testing.T) {
	for _, tc := range []struct {
		name string
		lists []string
		want bool
		wantHistory int
		wantLastState string
	}{
		{name: "first branch matched", lists: []string{"foo"}, want: true, wantHistory: 2, wantLastState: "hit"},
		{name: "no target matched", want: false, wantHistory: 2, wantLastState: "skipped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := netapi.WithContext(t.Context())
			store := netapi.GetContext(ctx)
			store.NewRuleMatch("rule", "rule")
			store.ConnOptions().AddLists(tc.lists...)
			m := NewAnd(NewOr("", List("foo"), List("bar")), notMatcher{List("baz")})
			template := buildMatchTraceTemplate(m)
			store.SetRuleMatchTemplate(template)
			actual := m.Match(ctx, nil)
			history := store.MatchHistory()[0].History
			if actual != tc.want || len(history) != tc.wantHistory {
				t.Fatalf("actual=%v history=%+v", actual, history)
			}
			replayed := contractconnection.ReconstructMatchTrace(template, history)
			if replayed == nil || (replayed.State == "hit") != actual ||
				replayed.Children[1].State != tc.wantLastState {
				t.Fatalf("trace does not match real matcher: %+v, actual=%v", replayed, actual)
			}
		})
	}
}

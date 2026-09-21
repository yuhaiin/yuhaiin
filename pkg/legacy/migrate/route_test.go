package migrate

import (
	"testing"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	schemaconfig "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
)

func TestConvertLegacyRuleSkipsUnsupportedNonEmptyGroup(t *testing.T) {
	legacy := schemaconfig.Rulev2_builder{
		Name: new("malformed"),
		Mode: schemaconfig.Mode_proxy.Enum(),
		Rules: []*schemaconfig.Or{
			schemaconfig.Or_builder{Rules: []*schemaconfig.Rule{nil}}.Build(),
		},
	}.Build()

	got := ConvertLegacyRule(legacy)
	if len(got.Rules) != 0 {
		t.Fatalf("unsupported-only group became a matcher: %#v", got.Rules)
	}
}

func TestConvertLegacyRulePreservesExplicitEmptyGroup(t *testing.T) {
	legacy := schemaconfig.Rulev2_builder{
		Name:  new("catch-all"),
		Rules: []*schemaconfig.Or{schemaconfig.Or_builder{}.Build()},
	}.Build()

	got := ConvertLegacyRule(legacy)
	want := []contractroute.RuleExpr{{Type: "all", All: nil}}
	if len(got.Rules) != 1 || got.Rules[0].Type != want[0].Type || len(got.Rules[0].All) != 0 {
		t.Fatalf("explicit empty group was not preserved: %#v", got.Rules)
	}
}

func TestConvertContractRuleRejectsUnknownEnum(t *testing.T) {
	if _, err := ConvertContractRule(contractroute.RouteRule{Name: "bad", Mode: "unknown"}); err == nil {
		t.Fatal("unknown route mode was silently converted")
	}
	if _, err := ConvertContractRule(contractroute.RouteRule{
		Name:  "bad-network",
		Rules: []contractroute.RuleExpr{{Type: "network", Network: &contractroute.NetworkExpr{Network: "icmp"}}},
	}); err == nil {
		t.Fatal("unknown network was silently converted")
	}
}

func TestConvertContractListRejectsUnknownTypeAndSource(t *testing.T) {
	if _, err := ConvertContractListDetail(contractroute.RouteListDetail{Name: "bad", Type: "cidr"}); err == nil {
		t.Fatal("unknown route list type was silently converted")
	}
	if _, err := ConvertContractListDetail(contractroute.RouteListDetail{Name: "bad", Type: "host", Source: contractroute.ListSource{Type: "generated"}}); err == nil {
		t.Fatal("unknown route list source was silently converted")
	}
}

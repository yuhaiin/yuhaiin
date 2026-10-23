package route

import "testing"

func TestConditionsRejectAmbiguousAndEmptyExpressions(t *testing.T) {
	for _, expr := range []RuleExpr{
		{}, {Type: "all", All: []RuleExpr{}}, {Type: "any", Any: []RuleExpr{}},
		{Type: "not"}, {Type: "unknown"}, {Type: "host", Host: &ListRef{}},
		{Type: "network", Network: &NetworkExpr{Network: "anything"}},
		{Type: "port", Port: &PortExpr{Ports: "443-80"}},
		{Type: "host", Host: &ListRef{List: "a"}, Network: &NetworkExpr{Network: "tcp"}},
		{Type: "user", User: &IdentityExpr{}},
		{Type: "group", Group: &IdentityExpr{IDs: []string{""}}},
		{Type: "credential", User: &IdentityExpr{IDs: []string{"alice"}}},
		{Type: "user", User: &IdentityExpr{IDs: []string{"alice"}}, Group: &IdentityExpr{IDs: []string{"finance"}}},
	} {
		if err := ValidateConditions([]RuleExpr{expr}); err == nil {
			t.Fatalf("accepted invalid expression: %+v", expr)
		}
	}
	if err := ValidateConditions(nil); err == nil {
		t.Fatal("implicit match-all accepted")
	}
}

func TestConditionsAcceptRecursiveCombinationsAndExplicitAllTraffic(t *testing.T) {
	expr := RuleExpr{Type: "all", All: []RuleExpr{
		{Type: "network", Network: &NetworkExpr{Network: "tcp"}},
		{Type: "any", Any: []RuleExpr{
			{Type: "port", Port: &PortExpr{Ports: "80,443,8000-8080"}},
			{Type: "not", Not: &RuleExpr{Type: "host", Host: &ListRef{List: "blocked"}}},
		}},
	}}
	if err := ValidateConditions([]RuleExpr{expr}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateConditions([]RuleExpr{{Type: "always"}}); err != nil {
		t.Fatal(err)
	}
	refs := []string{}
	if err := VisitListRefs([]RuleExpr{expr}, func(_, id string) error { refs = append(refs, id); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0] != "blocked" {
		t.Fatalf("nested references = %v", refs)
	}
}

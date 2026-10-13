package route

import (
	"context"
	"testing"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestInboundMatchingUsesStableIdentityAfterRename(t *testing.T) {
	ctx := netapi.WithContext(t.Context()).SetInboundID("entry-id").SetInboundName("Renamed entry")
	if !NewInbound("entry-id").Match(ctx, nil) {
		t.Fatal("stable inbound ID did not match after rename")
	}
	if NewInbound("Renamed entry").Match(ctx, nil) {
		t.Fatal("display name was used as identity")
	}
}

func TestNestedSort(t *testing.T) {
	rules := []contractroute.RuleExpr{
		{Type: "host", Host: &contractroute.ListRef{List: "host"}},
		{Type: "process", Process: &contractroute.ListRef{List: "process"}},
		{Type: "inbound", Inbound: &contractroute.SourceRef{Name: "mixed"}},
		{Type: "network", Network: &contractroute.NetworkExpr{Network: "tcp"}},
	}

	got := sortRule(rules)
	if got[0].Type != "network" || got[len(got)-1].Type != "host" {
		t.Fatalf("unexpected sort order: %#v", got)
	}
}

func TestRecursiveConditionsOnlyReadPreparedMatchContext(t *testing.T) {
	expr := contractroute.RuleExpr{Type: "all", All: []contractroute.RuleExpr{
		{Type: "network", Network: &contractroute.NetworkExpr{Network: "tcp"}},
		{Type: "any", Any: []contractroute.RuleExpr{
			{Type: "host", Host: &contractroute.ListRef{List: "work"}},
			{Type: "process", Process: &contractroute.ListRef{List: "browser"}},
		}},
		{Type: "not", Not: &contractroute.RuleExpr{Type: "host", Host: &contractroute.ListRef{List: "excluded"}}},
		{Type: "port", Port: &contractroute.PortExpr{Ports: "400-450"}},
	}}
	matcher := ParseMatcher(contractroute.RouteRule{Rules: []contractroute.RuleExpr{expr}})
	for _, tc := range []struct {
		name    string
		lists   []string
		network string
		port    uint16
		matched bool
	}{
		{"host", []string{"work"}, "tcp", 443, true},
		{"process", []string{"browser"}, "tcp", 443, true},
		{"excluded", []string{"work", "excluded"}, "tcp", 443, false},
		{"network", []string{"work"}, "udp", 443, false},
		{"port", []string{"work"}, "tcp", 451, false},
		{"missing", nil, "tcp", 443, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, state := netapi.GetOrNewContext(context.Background())
			state.ConnOptions().AddLists(tc.lists...)
			addr, err := netapi.ParseAddressPort(tc.network, "example.com", tc.port)
			if err != nil {
				t.Fatal(err)
			}
			if got := matcher.Match(ctx, addr); got != tc.matched {
				t.Fatalf("matched = %v, want %v", got, tc.matched)
			}
		})
	}
}

func TestUnknownAndEmptyConditionsNeverMatchAll(t *testing.T) {
	addr, err := netapi.ParseAddressPort("tcp", "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	for _, rules := range [][]contractroute.RuleExpr{nil, {{Type: "all"}}, {{Type: "any"}}, {{Type: "unknown"}}} {
		ctx, _ := netapi.GetOrNewContext(t.Context())
		if ParseMatcher(contractroute.RouteRule{Rules: rules}).Match(ctx, addr) {
			t.Fatalf("invalid conditions matched: %+v", rules)
		}
	}
	if !ParseMatcher(contractroute.RouteRule{Rules: []contractroute.RuleExpr{{Type: "always"}}}).Match(t.Context(), addr) {
		t.Fatal("explicit all-traffic condition did not match")
	}
}

package route

import (
	"testing"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

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

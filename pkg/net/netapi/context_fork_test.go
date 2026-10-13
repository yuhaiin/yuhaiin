package netapi

import "testing"

func TestDialForkIsolatesOptionsAndHistoryButRetainsRoutingIdentity(t *testing.T) {
	parent := WithContext(t.Context())
	parent.SetInboundID("inbound").SetMatchedRule("rule", "Work").SetSelector("selector", "Shared").SetGeo("JP")
	parent.NewRuleMatch("rule", "Work")
	parent.AddConditionHistory("list", "sites", "Websites", true)
	parent.ConnOptions().Resolver().SetMode(ResolverModePreferIPv4)
	child := ForkContext(parent)
	child.SetGeo("US")
	child.SetMatchedRule("nested", "Nested")
	child.ConnOptions().Resolver().SetMode(ResolverModePreferIPv6)
	child.ConnOptions().SetBindInterface("winner-interface")
	child.AddConditionHistory("list", "other", "Other data", false)
	child.Hash, child.NodeName = "winner", "Winning node"
	if parent.GetGeo() != "JP" || parent.ConnOptions().Resolver().Mode() != ResolverModePreferIPv4 || len(parent.MatchHistory()[0].History) != 1 {
		t.Fatal("attempt mutated parent metadata")
	}
	if child.GetInboundID() != "inbound" {
		t.Fatal("attempt lost inbound identity")
	}
	parent.AcceptDialResult(child)
	id, _ := parent.MatchedRule()
	selector, _ := parent.Selector()
	if parent.Hash != "winner" || parent.NodeName != "Winning node" || parent.ConnOptions().BindInterface() != "winner-interface" || id != "rule" || selector != "selector" {
		t.Fatal("winner metadata or routing identity lost")
	}
}

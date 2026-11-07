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

func TestRuleMatchReserveAndCompact(t *testing.T) {
	c := GetContext(WithContext(t.Context()))
	c.ReserveRuleMatches(20)
	allocs := testing.AllocsPerRun(1, func() {
		c.ruleChain = c.ruleChain[:0]
		for range 20 {
			c.NewRuleMatch("", "r")
		}
	})
	if allocs != 0 {
		t.Fatalf("reserved chain reallocated %v times", allocs)
	}

	c.ruleChain = c.ruleChain[:3]
	c.CompactRuleMatches()
	if len(c.ruleChain) != 3 || cap(c.ruleChain) != 3 {
		t.Fatalf("len=%d cap=%d after compact", len(c.ruleChain), cap(c.ruleChain))
	}

	// A forked child must not write into the parent's shared backing array.
	parent := GetContext(WithContext(t.Context()))
	parent.NewRuleMatch("p", "p")
	parent.ReserveRuleMatches(4)
	child := ForkContext(parent)
	child.ReserveRuleMatches(4)
	child.NewRuleMatch("c", "c")
	parent.NewRuleMatch("p2", "p2")
	if child.MatchHistory()[1].RuleID != "c" || parent.MatchHistory()[1].RuleID != "p2" {
		t.Fatalf("shared history corrupted: parent=%+v child=%+v", parent.MatchHistory(), child.MatchHistory())
	}
}

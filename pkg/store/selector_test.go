package store

import (
	"errors"
	"testing"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

func TestSelectorChangesSharedChoiceAndProtectsReferences(t *testing.T) {
	editor, _, _ := editorStore(t)
	nodes := NewNodeStore(editor.db)
	for _, id := range []string{"a", "b"} {
		node := contractnode.Node{ID: id, Name: id, Origin: "manual", Enabled: true, Chain: []contractnode.Protocol{{Type: "direct", Direct: &contractnode.Direct{}}}}
		if err := nodes.Save(t.Context(), node, 0); err != nil {
			t.Fatal(err)
		}
	}
	selectors := NewSelectorStore(editor.db)
	selected, err := selectors.Save(t.Context(), contractnode.Selector{Name: "Work", NodeID: "a"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"web", "apps"} {
		_, err := editor.Save(t.Context(), contractroute.RuleDraft{Rule: contractroute.RouteRule{ID: name, Name: name, Mode: "proxy", Target: contractroute.Target{Type: "selector", ID: selected.ID}, Rules: []contractroute.RuleExpr{{Type: "always"}}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	stale := selected
	selected.NodeID = "b"
	selected, err = selectors.Save(t.Context(), selected)
	if err != nil || selected.Revision != 2 {
		t.Fatalf("switch selected node = %+v, %v", selected, err)
	}
	if _, err := selectors.Save(t.Context(), stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale selector update = %v", err)
	}
	refs, err := selectors.References(t.Context(), selected.ID)
	if err != nil || len(refs) != 2 {
		t.Fatalf("selector references = %+v, %v", refs, err)
	}
	if _, ok := errors.AsType[*ResourceInUseError](selectors.Delete(t.Context(), selected.ID)); !ok {
		t.Fatal("referenced selector deleted")
	}
	if _, ok := errors.AsType[*ResourceInUseError](nodes.Delete(t.Context(), "b")); !ok {
		t.Fatal("selected node deleted")
	}
	if err := nodes.Delete(t.Context(), "a"); err != nil {
		t.Fatalf("previous node still referenced: %v", err)
	}
}

func TestRuleDestinationValidationDoesNotSavePartialConfiguration(t *testing.T) {
	editor, _, _ := editorStore(t)
	for _, target := range []contractroute.Target{{Type: "node", ID: "missing"}, {Type: "selector", ID: "missing"}, {Type: "default", ID: "unexpected"}, {Type: "unknown"}} {
		draft := contractroute.RuleDraft{Rule: contractroute.RouteRule{ID: "test", Name: "Test", Mode: "proxy", Target: target, Rules: []contractroute.RuleExpr{{Type: "always"}}}}
		if _, err := editor.Save(t.Context(), draft); err == nil {
			t.Fatalf("accepted target %+v", target)
		}
	}
	if _, err := editor.Get(t.Context(), "test"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invalid destination saved: %v", err)
	}
}

func TestSubscriptionRefreshPreservesSelectorAndRejectsRemovingItsNode(t *testing.T) {
	editor, _, _ := editorStore(t)
	nodes := NewNodeStore(editor.db)
	node := contractnode.Node{ID: "remote-a", Name: "Japan", Enabled: true, Chain: []contractnode.Protocol{{Type: "direct", Direct: &contractnode.Direct{}}}}
	if err := nodes.ReplaceRemote(t.Context(), "Subscription", []contractnode.Node{node}, 1); err != nil {
		t.Fatal(err)
	}
	selected, err := NewSelectorStore(editor.db).Save(t.Context(), contractnode.Selector{Name: "Work", NodeID: node.ID})
	if err != nil {
		t.Fatal(err)
	}
	node.Name = "Japan updated"
	if err := nodes.ReplaceRemote(t.Context(), "Subscription", []contractnode.Node{node}, 2); err != nil {
		t.Fatal(err)
	}
	got, err := NewSelectorStore(editor.db).Get(t.Context(), selected.ID)
	if err != nil || got.NodeID != node.ID {
		t.Fatalf("selector changed during refresh: %+v %v", got, err)
	}
	if _, ok := errors.AsType[*ResourceInUseError](nodes.ReplaceRemote(t.Context(), "Subscription", nil, 3)); !ok {
		t.Fatal("refresh removed a selected node")
	}
	if got, err := nodes.Get(t.Context(), node.ID); err != nil || got.Name != "Japan updated" {
		t.Fatalf("failed refresh changed old configuration: %+v %v", got, err)
	}
}

func TestAutomaticSelectorCandidateReferencesAndPolicyRoundTrip(t *testing.T) {
	editor, _, _ := editorStore(t)
	nodes := NewNodeStore(editor.db)
	for _, id := range []string{"a", "b"} {
		if err := nodes.Save(t.Context(), contractnode.Node{ID: id, Name: id, Origin: "manual", Enabled: true, Chain: []contractnode.Protocol{{Type: "direct", Direct: &contractnode.Direct{}}}}, 0); err != nil {
			t.Fatal(err)
		}
	}
	s := NewSelectorStore(editor.db)
	saved, err := s.Save(t.Context(), contractnode.Selector{Name: "Auto", NodeID: "a", Policy: &contractnode.SelectorPolicy{Mode: "weighted", Candidates: []contractnode.SelectorCandidate{{NodeID: "b", Enabled: true, Weight: 4}}}})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := s.Get(t.Context(), saved.ID)
	if err != nil || loaded.Policy == nil || loaded.Policy.Candidates[0].Weight != 4 {
		t.Fatal(loaded, err)
	}
	if err := nodes.Delete(t.Context(), "b"); err == nil {
		t.Fatal("deleted automatic selector candidate")
	}
	ids, err := nodes.UsingIDs(t.Context())
	if err != nil || len(ids) != 2 {
		t.Fatal(ids, err)
	}
	stale := saved
	saved.Policy.Candidates[0].NodeID = "missing"
	if _, err := s.Save(t.Context(), saved); err == nil {
		t.Fatal("accepted missing candidate")
	}
	if loaded, err = s.Get(t.Context(), saved.ID); err != nil || loaded.Revision != stale.Revision || loaded.Policy.Candidates[0].NodeID != "b" {
		t.Fatal("partial update", loaded, err)
	}
}

func TestNodeDependencyCycleIsRejectedAtomically(t *testing.T) {
	editor, _, _ := editorStore(t)
	nodes := NewNodeStore(editor.db)
	a := contractnode.Node{ID: "a", Name: "a", Origin: "manual", Enabled: true, Chain: []contractnode.Protocol{{Type: "direct", Direct: &contractnode.Direct{}}}}
	b := a
	b.ID, b.Name = "b", "b"
	if err := nodes.Save(t.Context(), a, 0); err != nil {
		t.Fatal(err)
	}
	b.Chain = []contractnode.Protocol{{Type: "set", Set: &contractnode.Set{Nodes: []string{"a"}}}}
	if err := nodes.Save(t.Context(), b, 0); err != nil {
		t.Fatal(err)
	}
	a.Chain = []contractnode.Protocol{{Type: "point_as_endpoint", PointAsEndpoint: &contractnode.PointAsEndpoint{Hash: "b"}}}
	if err := nodes.Save(t.Context(), a, 0); err == nil {
		t.Fatal("accepted Set -> endpoint -> Set cycle")
	}
	loaded, err := nodes.Get(t.Context(), "a")
	if err != nil || loaded.Chain[0].Type != "direct" {
		t.Fatal("failed save changed node", loaded, err)
	}
	a.Chain = []contractnode.Protocol{{Type: "network_split", NetworkSplit: &contractnode.NetworkSplit{TCP: &contractnode.Protocol{Type: "set", Set: &contractnode.Set{Nodes: []string{"a"}}}}}}
	if err := nodes.Save(t.Context(), a, 0); err == nil {
		t.Fatal("accepted nested self-reference")
	}
}

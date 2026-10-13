package store

import (
	"errors"
	"path/filepath"
	"testing"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func editorStore(t *testing.T) (*RouteEditorStore, *RouteListStore, *RouteRuleStore) {
	t.Helper()
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewRouteEditorStore(db.DB()), NewRouteListStore(db.DB()), NewRouteRuleStore(db.DB())
}

func privateDraft(id, name string) contractroute.RuleDraft {
	return contractroute.RuleDraft{
		Rule:  contractroute.RouteRule{ID: id, Name: name, Mode: "direct", Rules: []contractroute.RuleExpr{{Type: "host", Host: &contractroute.ListRef{List: id + "-hosts"}}}},
		Lists: []contractroute.RouteListDetail{{ID: id + "-hosts", Name: "Websites", Type: "host", Source: contractroute.ListSource{Type: "local", Local: &contractroute.LocalSource{Lists: []string{"example.com"}}}}},
	}
}

func TestRuleEditorRejectsInvalidActionsDNSAndStrategies(t *testing.T) {
	editor, _, _ := editorStore(t)
	for _, update := range []func(*contractroute.RouteRule){
		func(rule *contractroute.RouteRule) { rule.Mode = "bypass" },
		func(rule *contractroute.RouteRule) { rule.Resolver = "missing" },
		func(rule *contractroute.RouteRule) { rule.ResolveStrategy = "any_string" },
		func(rule *contractroute.RouteRule) { rule.UdpProxyFqdnStrategy = "any_string" },
	} {
		draft := privateDraft("invalid", "Invalid")
		update(&draft.Rule)
		if _, err := editor.Save(t.Context(), draft); err == nil {
			t.Fatal("invalid rule was persisted")
		}
		if _, err := editor.Get(t.Context(), draft.Rule.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("invalid rule left partial data: %v", err)
		}
	}
}

func TestRuleEditorOwnsListsAndKeepsIdentityOnRename(t *testing.T) {
	editor, lists, rules := editorStore(t)
	draft, err := editor.Save(t.Context(), privateDraft("rule-a", "Original"))
	if err != nil {
		t.Fatal(err)
	}
	if draft.Rule.Revision != 1 || draft.Lists[0].OwnerRuleID != "rule-a" {
		t.Fatalf("saved draft = %+v", draft)
	}
	shared, err := lists.ListRouteLists(t.Context())
	if err != nil || len(shared) != 0 {
		t.Fatalf("private lists exposed as shared: %+v, %v", shared, err)
	}
	draft.Rule.Name = "Renamed"
	draft, err = editor.Save(t.Context(), draft)
	if err != nil {
		t.Fatal(err)
	}
	got, err := editor.Get(t.Context(), "rule-a")
	if err != nil || got.Rule.Name != "Renamed" || got.Rule.Revision != 2 || len(got.Lists) != 1 {
		t.Fatalf("renamed draft = %+v, %v", got, err)
	}
	if err := rules.DeleteRule(t.Context(), draft.Rule.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := lists.GetRouteList(t.Context(), "rule-a-hosts"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("private list not removed: %v", err)
	}
}

func TestRuleEditorRejectsStaleEditsAndRollsBackInvalidLists(t *testing.T) {
	editor, lists, _ := editorStore(t)
	draft, err := editor.Save(t.Context(), privateDraft("rule-a", "Original"))
	if err != nil {
		t.Fatal(err)
	}
	stale := draft
	draft.Rule.Name = "Current"
	if _, err := editor.Save(t.Context(), draft); err != nil {
		t.Fatal(err)
	}
	if _, err := editor.Save(t.Context(), stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale save = %v", err)
	}
	invalid := privateDraft("rule-b", "Invalid")
	invalid.Rule.Rules[0].Host.List = "missing"
	if _, err := editor.Save(t.Context(), invalid); err == nil {
		t.Fatal("missing list accepted")
	}
	if _, err := editor.Get(t.Context(), "rule-b"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed transaction persisted rule: %v", err)
	}
	if _, err := lists.GetRouteList(t.Context(), "rule-b-hosts"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed transaction persisted list: %v", err)
	}
}

func TestRuleEditorRejectsCrossRuleOwnershipAndProtectsSharedReferences(t *testing.T) {
	editor, lists, _ := editorStore(t)
	draft, err := editor.Save(t.Context(), privateDraft("rule-a", "First"))
	if err != nil {
		t.Fatal(err)
	}
	second := privateDraft("rule-b", "Second")
	second.Rule.Rules[0].Host.List = draft.Lists[0].ID
	second.Lists = nil
	if _, err := editor.Save(t.Context(), second); err == nil {
		t.Fatal("cross-rule private reference accepted")
	}
	if err := lists.SaveRouteList(t.Context(), draft.Lists[0], 0); err == nil {
		t.Fatal("private list editable through shared store")
	}
	shared := draft.Lists[0]
	shared.ID, shared.Name, shared.OwnerRuleID = "shared", "Shared", ""
	if err := lists.SaveRouteList(t.Context(), shared, 0); err != nil {
		t.Fatal(err)
	}
	second.Rule.Rules = []contractroute.RuleExpr{{Type: "not", Not: &contractroute.RuleExpr{Type: "host", Host: &contractroute.ListRef{List: "shared"}}}}
	if _, err := editor.Save(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	err = lists.DeleteRouteList(t.Context(), "shared")
	inUse, ok := errors.AsType[*ResourceInUseError](err)
	if !ok || len(inUse.References) != 1 || inUse.References[0].ID != "rule-b" {
		t.Fatalf("shared deletion = %v", err)
	}
}

func TestRuleEditorPromotesCurrentDraftDataInOneSave(t *testing.T) {
	editor, lists, rules := editorStore(t)
	draft, err := editor.Save(t.Context(), privateDraft("work", "Original"))
	if err != nil {
		t.Fatal(err)
	}
	id := draft.Lists[0].ID
	draft.Rule.Name = "Updated rule"
	draft.Lists[0].Name = "Team websites"
	draft.Lists[0].Source.Local.Lists = []string{"new.example"}
	draft.ShareLists = []string{id}
	saved, err := editor.Save(t.Context(), draft)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Rule.Revision != 2 || len(saved.Lists) != 0 || len(saved.ShareLists) != 0 {
		t.Fatalf("saved = %+v", saved)
	}
	shared, err := lists.GetRouteList(t.Context(), id)
	if err != nil || shared.OwnerRuleID != "" || shared.Name != "Team websites" || shared.Source.Local.Lists[0] != "new.example" || shared.Revision != 1 {
		t.Fatalf("shared = %+v, %v", shared, err)
	}
	another := contractroute.RuleDraft{Rule: contractroute.RouteRule{ID: "another", Name: "Another", Mode: "direct", Rules: saved.Rule.Rules}}
	if _, err := editor.Save(t.Context(), another); err != nil {
		t.Fatal(err)
	}
	if err := rules.DeleteRule(t.Context(), "work"); err != nil {
		t.Fatal(err)
	}
	if _, err := lists.GetRouteList(t.Context(), id); err != nil {
		t.Fatal("shared data deleted with former owner", err)
	}
	if err := lists.DeleteRouteList(t.Context(), id); err == nil {
		t.Fatal("shared data referenced by another rule was deleted")
	}
}

func TestFailedPromotionDoesNotChangeOwnershipOrRule(t *testing.T) {
	editor, lists, _ := editorStore(t)
	saved, err := editor.Save(t.Context(), privateDraft("work", "Original"))
	if err != nil {
		t.Fatal(err)
	}
	stale := saved
	saved.Rule.Name = "Latest"
	if _, err := editor.Save(t.Context(), saved); err != nil {
		t.Fatal(err)
	}
	stale.ShareLists = []string{stale.Lists[0].ID}
	if _, err := editor.Save(t.Context(), stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale promotion = %v", err)
	}
	current, err := editor.Get(t.Context(), "work")
	if err != nil {
		t.Fatal(err)
	}
	current.ShareLists = []string{"not-owned"}
	if _, err := editor.Save(t.Context(), current); err == nil {
		t.Fatal("unowned data promoted")
	}
	list, err := lists.GetRouteList(t.Context(), current.Lists[0].ID)
	if err != nil || list.OwnerRuleID != "work" {
		t.Fatalf("failed save changed ownership: %+v, %v", list, err)
	}
}

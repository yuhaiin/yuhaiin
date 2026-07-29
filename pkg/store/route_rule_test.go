package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestRouteRuleStoreSavePriorityDelete(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	store := NewRouteRuleStore(sqliteStore.DB())
	first := contractroute.RouteRule{Name: "first", Mode: "bypass", Tag: "direct", Rules: []contractroute.RuleExpr{{Type: "host", Host: &contractroute.ListRef{List: "cn"}}}}
	second := contractroute.RouteRule{Name: "second", Mode: "proxy", Tag: "node", Rules: []contractroute.RuleExpr{{Type: "inbound", Inbound: &contractroute.SourceRef{Name: "mixed"}}}}
	if err := store.SaveRule(ctx, first, 0, 100); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRule(ctx, second, 0, 100); err != nil {
		t.Fatal(err)
	}

	if err := store.ChangePriority(ctx, "second", "first", "insert_before"); err != nil {
		t.Fatal(err)
	}
	list, err := store.ListRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Rule.Name != "second" || list[0].Priority != 1 || list[1].Rule.Name != "first" || list[1].Priority != 2 {
		t.Fatalf("rules after priority change = %+v", list)
	}

	if err := store.DeleteRule(ctx, "second"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetRule(ctx, "second"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetRule after delete error = %v", err)
	}
	list, err = store.ListRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Rule.Name != "first" || list[0].Priority != 1 {
		t.Fatalf("rules after delete = %+v", list)
	}
}

func TestRouteRuleStoreListPageUsesDatabasePaginationAndQuery(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	store := NewRouteRuleStore(sqliteStore.DB())
	for _, rule := range []contractroute.RouteRule{
		{Name: "rule-a", Mode: "bypass", Tag: "direct", Resolver: "dns-a", Rules: []contractroute.RuleExpr{{Type: "host", Host: &contractroute.ListRef{List: "cn"}}}},
		{Name: "rule-b", Mode: "proxy", Tag: "node", Resolver: "dns-b", Rules: []contractroute.RuleExpr{{Type: "host", Host: &contractroute.ListRef{List: "global"}}}},
	} {
		if err := store.SaveRule(ctx, rule, 0, 100); err != nil {
			t.Fatal(err)
		}
	}

	items, total, err := store.ListRulesPage(ctx, "", 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(items) != 1 || items[0].Rule.Name != "rule-b" {
		t.Fatalf("page = %+v, total = %d", items, total)
	}
	items, total, err = store.ListRulesPage(ctx, "dns-b", 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(items) != 1 || items[0].Rule.Name != "rule-b" {
		t.Fatalf("query page = %+v, total = %d", items, total)
	}
}

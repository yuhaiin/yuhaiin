package sqlite

import (
	"database/sql"
	json "encoding/json/v2"
	"path/filepath"
	"strings"
	"testing"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

func databaseBeforeRouteUpgrade(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open(driverName, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if err := configure(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err := bootstrapBase(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations {
		if migration.Version < 10 {
			if err := applyMigration(t.Context(), db, migration); err != nil {
				t.Fatal(err)
			}
		}
	}
	return db
}

func TestRouteUpgradeFlattensAliasesAndRemovesObsoleteStorage(t *testing.T) {
	db := databaseBeforeRouteUpgrade(t)
	for _, id := range []string{"node-a", "node-b"} {
		if _, err := db.ExecContext(t.Context(), `INSERT INTO nodes_v2(id, name, group_name, origin, enabled, chain_types_json, updated_at, data_json) VALUES (?, ?, 'manual', 'manual', 1, '["direct"]', 1, ?)`, id, id, `{"id":"`+id+`","name":"`+id+`","enabled":true,"origin":"manual","chain":[{"type":"direct","direct":{}}]}`); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct{ name, value string }{
		{"root", `{"type":"node","hash":["node-a","node-b"]}`},
		{"alias", `{"type":"mirror","hash":["root"]}`},
		{"nested", `{"type":"mirror","hash":["alias"]}`},
	} {
		if _, err := db.ExecContext(t.Context(), `INSERT INTO node_tags_v2(id, name, members_json, updated_at) VALUES (?, ?, ?, 1)`, item.name, item.name, item.value); err != nil {
			t.Fatal(err)
		}
	}
	for i, name := range []string{"alias", "nested"} {
		if _, err := db.ExecContext(t.Context(), `INSERT INTO route_rules_v2(id, name, priority, disabled, action_mode, match_type, tag, revision, updated_at, data_json) VALUES (?, ?, ?, 0, 'proxy', 'all', ?, 1, 1, ?)`, name, name, i+1, name, `{"id":"`+name+`","name":"`+name+`","mode":"proxy","tag":"`+name+`","rules":[{"type":"all","all":[]}]}`); err != nil {
			t.Fatal(err)
		}
	}
	if err := Bootstrap(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM outbound_selectors`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("shared selector count = %d, %v", count, err)
	}
	for _, id := range []string{"alias", "nested"} {
		var value string
		if err := db.QueryRowContext(t.Context(), `SELECT data_json FROM route_rules_v2 WHERE id = ?`, id).Scan(&value); err != nil {
			t.Fatal(err)
		}
		var rule contractroute.RouteRule
		if err := json.Unmarshal([]byte(value), &rule); err != nil {
			t.Fatal(err)
		}
		if rule.Target.Type != "selector" || rule.Target.ID != "legacy-selector:root" || rule.Rules[0].Type != "always" || strings.Contains(value, `"tag"`) {
			t.Fatalf("upgraded rule = %s", value)
		}
	}
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE name = 'node_tags_v2'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("obsolete table remains: %d, %v", count, err)
	}
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pragma_table_info('route_rules_v2') WHERE name = 'tag'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("obsolete rule column remains: %d, %v", count, err)
	}
}

func TestRouteUpgradeRejectsAliasCyclesWithoutChangingConfiguration(t *testing.T) {
	db := databaseBeforeRouteUpgrade(t)
	for _, item := range []struct{ name, target string }{{"a", "b"}, {"b", "a"}} {
		if _, err := db.ExecContext(t.Context(), `INSERT INTO node_tags_v2(id, name, members_json, updated_at) VALUES (?, ?, ?, 1)`, item.name, item.name, `{"type":"mirror","hash":["`+item.target+`"]}`); err != nil {
			t.Fatal(err)
		}
	}
	if err := Bootstrap(t.Context(), db); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cyclic upgrade = %v", err)
	}
	var count int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM node_tags_v2`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("failed upgrade changed old bindings: %d, %v", count, err)
	}
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM migrate WHERE version = 10`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed upgrade marked complete: %d, %v", count, err)
	}
}

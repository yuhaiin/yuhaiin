package sqlite

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

func TestFakeDNSInlineListsMigrateToSharedLists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := sql.Open(driverName, path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if err := configure(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err := bootstrapBase(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations {
		if migration.Version >= fakeDNSSharedListsMigration.Version {
			break
		}
		if err := applyMigration(t.Context(), db, migration); err != nil {
			t.Fatal(err)
		}
	}
	for _, statement := range []string{
		`INSERT INTO dns_fakedns_lists(kind, value) VALUES ('whitelist', '*.tailscale.com'), ('whitelist', 'time.apple.com'), ('skip_check', 'local.test.t.com')`,
		// The user already has a list with the preferred name; it must survive.
		`INSERT INTO route_lists_v2(id, name, owner_rule_id, list_type, source_type, updated_at, data_json)
		 VALUES ('mine', 'FakeDNS whitelist', NULL, 'host', 'local', 1, '{"id":"mine","name":"FakeDNS whitelist","type":"host","source":{"type":"local","local":{"lists":["keep.example"]}}}')`,
	} {
		if _, err := db.ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	assertFakeDNSListsConverted(t, store.DB(), map[string][]string{
		"whitelist_list:fakedns-whitelist":   {"*.tailscale.com", "time.apple.com"},
		"skip_check_list:fakedns-skip-check": {"local.test.t.com"},
	})
	if name := queryString(t, store.DB(), `SELECT name FROM route_lists_v2 WHERE id = 'fakedns-whitelist'`); name != "FakeDNS whitelist 2" {
		t.Fatalf("converted list name = %q", name)
	}
	if data := queryString(t, store.DB(), `SELECT data_json FROM route_lists_v2 WHERE id = 'mine'`); !json.Valid([]byte(data)) || queryInt(t, store.DB(), `SELECT count(*) FROM route_lists_v2 WHERE id = 'mine' AND name = 'FakeDNS whitelist'`) != 1 {
		t.Fatal("existing list with the same name was changed")
	}
}

func TestConfigurationRestoreConvertsInlineFakeDNSLists(t *testing.T) {
	source, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	// Rows as exported by a Core that predates the shared-lists migration.
	if _, err := source.DB().ExecContext(t.Context(), `INSERT INTO dns_fakedns_lists(kind, value) VALUES ('whitelist', 'mask.icloud.com')`); err != nil {
		t.Fatal(err)
	}
	data, err := ExportConfig(t.Context(), source.DB())
	if err != nil {
		t.Fatal(err)
	}
	target, err := Open(t.Context(), filepath.Join(t.TempDir(), "restored.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := RestoreConfig(t.Context(), target.DB(), data); err != nil {
		t.Fatal(err)
	}
	assertFakeDNSListsConverted(t, target.DB(), map[string][]string{"whitelist_list:fakedns-whitelist": {"mask.icloud.com"}})
}

// assertFakeDNSListsConverted checks that no inline rows remain and that each
// "kind:id" reference points to a shared host list with exactly those entries.
func assertFakeDNSListsConverted(t *testing.T, db *sql.DB, want map[string][]string) {
	t.Helper()
	if n := queryInt(t, db, `SELECT count(*) FROM dns_fakedns_lists WHERE kind IN ('whitelist', 'skip_check')`); n != 0 {
		t.Fatalf("%d inline FakeDNS rows remain", n)
	}
	if n := queryInt(t, db, `SELECT count(*) FROM dns_fakedns_lists`); n != int64(len(want)) {
		t.Fatalf("FakeDNS references = %d, want %d", n, len(want))
	}
	for ref, values := range want {
		var kind, id string
		for i := range ref {
			if ref[i] == ':' {
				kind, id = ref[:i], ref[i+1:]
				break
			}
		}
		if queryInt(t, db, `SELECT count(*) FROM dns_fakedns_lists WHERE kind = ? AND value = ?`, kind, id) != 1 {
			t.Fatalf("missing reference %s", ref)
		}
		var list contractroute.RouteListDetail
		if err := json.Unmarshal([]byte(queryString(t, db, `SELECT data_json FROM route_lists_v2 WHERE id = ? AND owner_rule_id IS NULL AND list_type = 'host'`, id)), &list); err != nil {
			t.Fatal(err)
		}
		if list.ID != id || list.Source.Local == nil || !slices.Equal(list.Source.Local.Lists, values) {
			t.Fatalf("list %s = %+v", id, list)
		}
	}
}

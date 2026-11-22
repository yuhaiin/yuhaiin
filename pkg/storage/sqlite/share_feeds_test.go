package sqlite

import (
	"database/sql"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"path/filepath"
	"slices"
	"testing"

	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
)

func databaseBeforeShareFeeds(t *testing.T) *sql.DB {
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
		if migration.Version < shareFeedsMigration.Version {
			if err := applyMigration(t.Context(), db, migration); err != nil {
				t.Fatal(err)
			}
		}
	}
	return db
}

func TestShareFeedsMigrationConvertsPublishes(t *testing.T) {
	db := databaseBeforeShareFeeds(t)
	for _, row := range []struct{ name, data string }{
		{"friends", `{"name":"friends","points":["a","b","a"],"path":"p","password":"pw","address":"example.com:8443","insecure":false}`},
		{"lan", `{"name":"lan","points":[],"address":"192.168.1.2","insecure":true}`},
		{"broken", `not json`},
	} {
		if _, err := db.ExecContext(t.Context(), `INSERT INTO publishes(name, updated_at, data_json) VALUES (?, 7, json_quote(?))`, row.name, row.data); err != nil {
			t.Fatal(err)
		}
		if row.name != "broken" {
			if _, err := db.ExecContext(t.Context(), `UPDATE publishes SET data_json = ? WHERE name = ?`, row.data, row.name); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := Bootstrap(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if schemaObjectExists(t, db, "publishes") {
		t.Fatal("publishes table survived the migration")
	}
	rows, err := db.QueryContext(t.Context(), `SELECT id, updated_at, data_json FROM share_feeds`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	feeds := map[string]contractsubscription.ShareFeed{}
	for rows.Next() {
		var id, data string
		var updatedAt int64
		if err := rows.Scan(&id, &updatedAt, &data); err != nil {
			t.Fatal(err)
		}
		var feed contractsubscription.ShareFeed
		if err := json.Unmarshal([]byte(data), &feed); err != nil {
			t.Fatal(err)
		}
		if feed.ID != id || updatedAt != 7 || feed.Token == "" || !feed.Enabled {
			t.Fatalf("migrated feed %s = %+v", id, feed)
		}
		feeds[feed.Name] = feed
	}
	if len(feeds) != 2 {
		t.Fatalf("migrated feeds = %+v", feeds)
	}
	friends := feeds["friends"]
	wantEntries := []contractsubscription.ShareFeedEntry{{Kind: "node", Value: "a"}, {Kind: "node", Value: "b"}}
	if friends.BaseURL != "https://example.com:8443" || !slices.Equal(friends.Entries, wantEntries) {
		t.Fatalf("friends = %+v", friends)
	}
	if lan := feeds["lan"]; lan.BaseURL != "http://192.168.1.2" || len(lan.Entries) != 0 {
		t.Fatalf("lan = %+v", lan)
	}
}

func TestConfigBackupUpgradesLegacyPublishes(t *testing.T) {
	store, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	exported, err := ExportConfig(t.Context(), store.DB())
	if err != nil {
		t.Fatal(err)
	}
	var backup map[string]jsontext.Value
	if err := json.Unmarshal(exported, &backup); err != nil {
		t.Fatal(err)
	}
	var tables map[string]jsontext.Value
	if err := json.Unmarshal(backup["tables"], &tables); err != nil {
		t.Fatal(err)
	}
	delete(tables, "share_feeds")
	tables["publishes"] = jsontext.Value(`{"columns":["name","updated_at","data_json"],"rows":[["old",3,"{\"name\":\"old\",\"points\":[\"n\"],\"address\":\"example.com\"}"]]}`)
	backup["tables"], err = json.Marshal(tables)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := RestoreConfig(t.Context(), store.DB(), legacy); err != nil {
		t.Fatal(err)
	}
	var data string
	if err := store.DB().QueryRowContext(t.Context(), `SELECT data_json FROM share_feeds`).Scan(&data); err != nil {
		t.Fatal(err)
	}
	var feed contractsubscription.ShareFeed
	if err := json.Unmarshal([]byte(data), &feed); err != nil {
		t.Fatal(err)
	}
	if feed.Name != "old" || feed.BaseURL != "https://example.com" || len(feed.Entries) != 1 || feed.Entries[0].Value != "n" {
		t.Fatalf("restored feed = %+v", feed)
	}
}

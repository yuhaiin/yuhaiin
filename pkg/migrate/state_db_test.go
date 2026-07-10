package migrate

import (
	"context"
	"database/sql"
	"encoding/binary"
	json "encoding/json/v2"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/cache/memory"
	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	legacymigrate "github.com/Asutorufa/yuhaiin/pkg/legacy/migrate"
	legacynode "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestStateDBRequiresExplicitStartupMigration(t *testing.T) {
	ctx := context.Background()
	statePath := filepath.Join(t.TempDir(), "state.db")
	state := NewStateDB(statePath)
	defer func() { _ = state.Close() }()

	if _, err := state.SQLDB(ctx); err == nil || !strings.Contains(err.Error(), "plain model migration has not run") {
		t.Fatalf("SQLDB before Migrate error = %v", err)
	}

	if err := state.Migrate(ctx); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}
	db, err := state.SQLDB(ctx)
	if err != nil {
		t.Fatalf("SQLDB after Migrate failed: %v", err)
	}
	assertStateMarker(t, ctx, db, plainModelMigrationDoneKey)
}

func TestStateDBMigrateRewritesLegacyConnectionHistory(t *testing.T) {
	ctx := context.Background()
	statePath := filepath.Join(t.TempDir(), "state.db")

	store, err := storagesqlite.Open(ctx, statePath)
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}
	legacyJSON := `{"id":123,"addr":"example.com:443","pid":456,"uid":789,"udp_migrate_id":42,"type":{"conn_type":1},"hash":"node-a","node_name":"Node A","mode":2}`
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO connection_history(protocol, addr, process_name, hit_count, last_seen_at, last_connection_json)
		VALUES (?, ?, ?, ?, ?, ?)
	`, "tcp", "example.com:443", "curl", 1, 100, legacyJSON); err != nil {
		t.Fatalf("insert legacy history failed: %v", err)
	}
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO connection_sessions(
			id, opened_at, last_seen_at, state, protocol, process_name, summary_json
		)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, 123, 90, 100, "open", "tcp", "curl", legacyJSON); err != nil {
		t.Fatalf("insert legacy session failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seed sqlite failed: %v", err)
	}

	state := NewStateDB(statePath)
	defer func() { _ = state.Close() }()
	if err := state.Migrate(ctx); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}
	db, err := state.SQLDB(ctx)
	if err != nil {
		t.Fatalf("SQLDB after Migrate failed: %v", err)
	}
	assertStateMarker(t, ctx, db, legacymigrate.PlainStatisticJSONMigrationDoneKey)

	assertConnectionJSONStrings(t, ctx, db, "connection_history", "last_connection_json")
	var sessionCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM connection_sessions`).Scan(&sessionCount); err != nil {
		t.Fatal(err)
	}
	if sessionCount != 1 {
		t.Fatalf("connection sessions after migration = %d, want 1", sessionCount)
	}
}

func TestStateDBMigrateLeavesSessionCleanupToStatisticsStartup(t *testing.T) {
	ctx := context.Background()
	statePath := filepath.Join(t.TempDir(), "state.db")

	store, err := storagesqlite.Open(ctx, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO metadata(key, value) VALUES (?, '1')
	`, plainModelMigrationDoneKey); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO connection_sessions(
			id, opened_at, last_seen_at, state, protocol, summary_json
		) VALUES (1, 1, 1, 'open', 'tcp', '{}')
	`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	state := NewStateDB(statePath)
	defer func() { _ = state.Close() }()
	if err := state.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := state.SQLDB(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var sessionCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM connection_sessions`).Scan(&sessionCount); err != nil {
		t.Fatal(err)
	}
	if sessionCount != 1 {
		t.Fatalf("connection sessions after migration = %d, want 1", sessionCount)
	}
}

func TestStateDBMigrateLegacyPebbleBeforeRuntime(t *testing.T) {
	ctx := context.Background()
	state := NewStateDB(filepath.Join(t.TempDir(), "state.db"))
	defer func() { _ = state.Close() }()
	if err := state.Migrate(ctx); err != nil {
		t.Fatalf("migrate sqlite state: %v", err)
	}

	legacy := memory.NewMemoryCache()
	flow := legacy.NewCache("flow_data")
	if err := flow.Put([]byte("DOWNLOAD"), binary.BigEndian.AppendUint64(nil, 123)); err != nil {
		t.Fatal(err)
	}
	if err := flow.Put([]byte("UPLOAD"), binary.BigEndian.AppendUint64(nil, 456)); err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("10.42.0.0/24")
	if err := legacy.NewCache(prefix.String()).Put([]byte("old.example"), netip.MustParseAddr("10.42.0.2").AsSlice()); err != nil {
		t.Fatal(err)
	}

	if err := state.MigrateLegacyPebble(ctx, legacy, prefix, netip.MustParsePrefix("fd00::/120")); err != nil {
		t.Fatalf("migrate pebble state: %v", err)
	}
	db, err := state.SQLDB(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var download, upload uint64
	if err := db.QueryRowContext(ctx, `SELECT value_int FROM statistics_kv WHERE key = 'total_download'`).Scan(&download); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT value_int FROM statistics_kv WHERE key = 'total_upload'`).Scan(&upload); err != nil {
		t.Fatal(err)
	}
	if download != 123 || upload != 456 {
		t.Fatalf("unexpected migrated totals download=%d upload=%d", download, upload)
	}
	var domain string
	if err := db.QueryRowContext(ctx, `SELECT domain FROM fakeip_entries WHERE family = 4 AND prefix = ?`, prefix.String()).Scan(&domain); err != nil {
		t.Fatal(err)
	}
	if domain != "old.example" {
		t.Fatalf("unexpected migrated fakeip domain %q", domain)
	}
}

func TestStateDBMigrateNormalizesLegacyRouteRefreshConfig(t *testing.T) {
	ctx := context.Background()
	statePath := filepath.Join(t.TempDir(), "state.db")
	store, err := storagesqlite.Open(ctx, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO settings_kv(section, key, value_json, updated_at)
		VALUES ('route_extra', 'refresh_config', ?, 1)
	`, `{"refresh_interval":"3600","last_refresh_time":"42","error":"old error"}`); err != nil {
		t.Fatal(err)
	}
	for _, value := range []struct {
		section string
		key     string
		json    string
	}{
		{"general", "ipv6", `"true"`},
		{"advanced", "udp_buffer_size", `"4096"`},
		{"logcat", "level", `"info"`},
	} {
		if _, err := store.DB().ExecContext(ctx, `
			INSERT INTO settings_kv(section, key, value_json, updated_at)
			VALUES (?, ?, ?, 1)
		`, value.section, value.key, value.json); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO metadata(key, value) VALUES (?, '1')
	`, plainModelMigrationDoneKey); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	state := NewStateDB(statePath)
	defer func() { _ = state.Close() }()
	if err := state.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := state.SQLDB(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var data string
	if err := db.QueryRowContext(ctx, `
		SELECT value_json FROM settings_kv
		WHERE section = 'route_extra' AND key = 'refresh_config'
	`).Scan(&data); err != nil {
		t.Fatal(err)
	}
	var refresh struct {
		RefreshInterval uint64 `json:"refresh_interval"`
		LastRefreshTime uint64 `json:"last_refresh_time"`
		Error           string `json:"error"`
	}
	if err := json.Unmarshal([]byte(data), &refresh); err != nil {
		t.Fatal(err)
	}
	if refresh.RefreshInterval != 3600 || refresh.LastRefreshTime != 42 || refresh.Error != "old error" {
		t.Fatalf("unexpected canonical refresh config: %+v", refresh)
	}
	var ipv6 bool
	if err := db.QueryRowContext(ctx, `SELECT value_json FROM settings_kv WHERE section = 'general' AND key = 'ipv6'`).Scan(&data); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(data), &ipv6); err != nil || !ipv6 {
		t.Fatalf("unexpected canonical ipv6 value %q: %v", data, err)
	}
	var udpBuffer, logLevel int32
	if err := db.QueryRowContext(ctx, `SELECT value_json FROM settings_kv WHERE section = 'advanced' AND key = 'udp_buffer_size'`).Scan(&data); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(data), &udpBuffer); err != nil || udpBuffer != 4096 {
		t.Fatalf("unexpected canonical udp buffer %q: %v", data, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT value_json FROM settings_kv WHERE section = 'logcat' AND key = 'level'`).Scan(&data); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(data), &logLevel); err != nil || logLevel != 2 {
		t.Fatalf("unexpected canonical log level %q: %v", data, err)
	}
}

func TestStateDBMigrateImportsLegacyNodeJSONWithoutStateDB(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	hash := "hash-1"
	point := legacynode.Point_builder{
		Hash:   &hash,
		Name:   stringPtr("alpha-node"),
		Group:  stringPtr("remote-group"),
		Origin: legacynode.Origin_remote.Enum(),
	}.Build()
	legacy := legacynode.Node_builder{
		Tcp: point,
		Udp: point,
		Manager: (&legacynode.Manager_builder{
			Nodes: map[string]*legacynode.Point{
				hash: point,
			},
			Tags: map[string]*legacynode.Tags{
				"fast": legacynode.Tags_builder{
					Tag:  stringPtr("fast"),
					Type: legacynode.TagType_node.Enum(),
					Hash: []string{hash},
				}.Build(),
			},
			Publishes: map[string]*legacynode.Publish{
				"pub": legacynode.Publish_builder{
					Name:     stringPtr("pub"),
					Path:     stringPtr("/pub"),
					Password: stringPtr("secret"),
					Points:   []string{hash},
				}.Build(),
			},
		}).Build(),
		Links: map[string]*legacynode.Link{
			"remote-group": legacynode.Link_builder{
				Name: stringPtr("remote-group"),
				Url:  stringPtr("https://example.com/sub.txt"),
			}.Build(),
		},
	}.Build()
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy node json failed: %v", err)
	}
	if err := os.WriteFile(paths.PathGenerator.Node(dir), data, 0o600); err != nil {
		t.Fatalf("write legacy node json failed: %v", err)
	}

	state := NewStateDB(paths.PathGenerator.State(dir))
	defer func() { _ = state.Close() }()
	if err := state.Migrate(ctx); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}
	db, err := state.SQLDB(ctx)
	if err != nil {
		t.Fatalf("SQLDB after Migrate failed: %v", err)
	}

	got, err := plainstore.NewNodeStore(db).Get(ctx, hash)
	if err != nil {
		t.Fatalf("get migrated node failed: %v", err)
	}
	if got.ID != hash || got.Name != "alpha-node" || got.Group != "remote-group" || got.Origin != "remote" {
		t.Fatalf("migrated node = %+v", got)
	}
	assertStateMetadataValue(t, ctx, db, "selected_tcp_node_v2", hash)
	assertStateMetadataValue(t, ctx, db, "selected_udp_node_v2", hash)
	assertStateMetadataValue(t, ctx, db, "legacy_node_import_source", "node.json")

	var tagMembers string
	if err := db.QueryRowContext(ctx, `SELECT members_json FROM node_tags_v2 WHERE name = 'fast'`).Scan(&tagMembers); err != nil {
		t.Fatalf("query migrated node tag failed: %v", err)
	}
	if !strings.Contains(tagMembers, hash) {
		t.Fatalf("migrated tag members = %s, want %q", tagMembers, hash)
	}
}

func assertStateMarker(t *testing.T, ctx context.Context, db *sql.DB, key string) {
	t.Helper()
	var value string
	err := db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("marker %q not found", key)
	}
	if err != nil {
		t.Fatalf("query marker %q failed: %v", key, err)
	}
	if value != "1" {
		t.Fatalf("marker %q = %q, want 1", key, value)
	}
}

func assertStateMetadataValue(t *testing.T, ctx context.Context, db *sql.DB, key, want string) {
	t.Helper()
	var value string
	err := db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key = ?`, key).Scan(&value)
	if err != nil {
		t.Fatalf("query metadata %q failed: %v", key, err)
	}
	if value != want {
		t.Fatalf("metadata %q = %q, want %q", key, value, want)
	}
}

func stringPtr(value string) *string {
	return &value
}

func assertConnectionJSONStrings(t *testing.T, ctx context.Context, db *sql.DB, table, column string) {
	t.Helper()
	var data string
	if err := db.QueryRowContext(ctx, "SELECT "+column+" FROM "+table+" LIMIT 1").Scan(&data); err != nil {
		t.Fatalf("query %s.%s failed: %v", table, column, err)
	}
	var conn contractconnection.Connection
	if err := json.Unmarshal([]byte(data), &conn); err != nil {
		t.Fatalf("decode migrated %s.%s failed: %v; json=%s", table, column, err, data)
	}
	if conn.ID != "123" || conn.PID != "456" || conn.UID != "789" || conn.UDPMigrateID != "42" || conn.Mode != "proxy" || conn.Network.ConnType != "tcp" || conn.NodeID != "node-a" || conn.NodeName != "Node A" {
		t.Fatalf("migrated %s.%s connection = %#v", table, column, conn)
	}
	if strings.Contains(data, `"id":123`) || strings.Contains(data, `"pid":456`) || strings.Contains(data, `"uid":789`) || strings.Contains(data, `"mode":2`) {
		t.Fatalf("migrated %s.%s still contains numeric string fields: %s", table, column, data)
	}
}

package migrate

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
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

func TestStateDBMigrateRewritesLegacyStatisticConnectionIDs(t *testing.T) {
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
	assertStateMarker(t, ctx, db, plainStatisticJSONMigrationDoneKey)

	assertConnectionJSONStrings(t, ctx, db, "connection_history", "last_connection_json")
	assertConnectionJSONStrings(t, ctx, db, "connection_sessions", "summary_json")
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

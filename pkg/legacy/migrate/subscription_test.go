package migrate

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"path/filepath"
	"testing"

	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
	legacy "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestMigrateLegacySubscriptionsRewritesEnumType(t *testing.T) {
	ctx := context.Background()
	store, err := storagesqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	name, url := "aws-share", "https://example.com/sub"
	legacyLink := (&legacy.Link_builder{
		Name: &name,
		Url:  &url,
		Type: legacy.Type_trojan.Enum(),
	}).Build()
	data, err := json.Marshal(legacyLink)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO subscriptions(name, updated_at, data_json)
		VALUES (?, ?, ?)
	`, name, 1, string(data)); err != nil {
		t.Fatal(err)
	}

	if err := MigrateLegacySubscriptions(ctx, store.DB(), 2); err != nil {
		t.Fatal(err)
	}

	var migrated string
	if err := store.DB().QueryRowContext(ctx, `SELECT data_json FROM subscriptions WHERE name = ?`, name).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	var link contractsubscription.Link
	if err := json.Unmarshal([]byte(migrated), &link); err != nil {
		t.Fatalf("decode migrated contract link: %v; json=%s", err, migrated)
	}
	if link.Type != "trojan" || link.URL != url {
		t.Fatalf("migrated link = %+v", link)
	}

	var marker string
	if err := store.DB().QueryRowContext(ctx, `
		SELECT value FROM metadata WHERE key = 'plain_subscriptions_migration_done'
	`).Scan(&marker); err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	if marker != "1" {
		t.Fatalf("migration marker = %q", marker)
	}
}

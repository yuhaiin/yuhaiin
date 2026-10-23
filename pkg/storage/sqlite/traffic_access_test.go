package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"testing"
)

func TestTrafficAccessMigrationRollsBackAndRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "management.db")
	old, err := open(t.Context(), path, "management", func(ctx context.Context, db *sql.DB) error {
		if err := bootstrapBase(ctx, db); err != nil {
			return err
		}
		for _, m := range []Migration{managementAuthMigration, managementInitializationMigration, proxyCredentialsMigration, managementOAuthMigration, managementAuditMigration, trafficGroupsMigration} {
			if err := applyMigration(ctx, db, m); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	broken := trafficAccessMigration
	broken.Statements = append(slices.Clone(broken.Statements), "INTERRUPTED MIGRATION")
	if err := applyMigration(t.Context(), old.DB(), broken); err == nil {
		t.Fatal("interrupted migration succeeded")
	}
	if schemaObjectExists(t, old.DB(), "traffic_access_config") || queryInt(t, old.DB(), `SELECT count(*) FROM migrate`) != 6 {
		t.Fatal("partial authorization migration committed")
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := OpenManagement(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if !schemaObjectExists(t, upgraded.DB(), "traffic_access_config") || queryInt(t, upgraded.DB(), `SELECT count(*) FROM migrate`) != 7 {
		t.Fatal("migration missing")
	}
	if err := upgraded.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenManagement(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if queryInt(t, restarted.DB(), `SELECT count(*) FROM migrate`) != 7 {
		t.Fatal("migration repeated")
	}
}

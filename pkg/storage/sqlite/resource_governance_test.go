package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"testing"
)

func TestResourceMigrationInterruptedAndRestarted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "management.db")
	old, err := open(t.Context(), path, "management", func(ctx context.Context, db *sql.DB) error {
		if err := bootstrapBase(ctx, db); err != nil {
			return err
		}
		for _, m := range []Migration{managementAuthMigration, managementInitializationMigration, proxyCredentialsMigration, managementOAuthMigration, managementAuditMigration, trafficGroupsMigration, trafficAccessMigration} {
			if err := applyMigration(ctx, db, m); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	broken := resourceGovernanceMigration
	broken.Statements = append(slices.Clone(broken.Statements), "INTERRUPTED MIGRATION")
	if err := applyMigration(t.Context(), old.DB(), broken); err == nil {
		t.Fatal("interrupted migration committed")
	}
	if schemaObjectExists(t, old.DB(), "quota_windows") || queryInt(t, old.DB(), `SELECT count(*) FROM migrate`) != 7 {
		t.Fatal("partial resource schema committed")
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		db, err := OpenManagement(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		if !schemaObjectExists(t, db.DB(), "quota_windows") || queryInt(t, db.DB(), `SELECT count(*) FROM migrate`) != int64(managementSecurityAuditMigration.Version) {
			t.Fatal("resource migration missing or repeated")
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"testing"
)

func TestTrafficGroupsMigrationRestartAndInterruptedTransaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "management.db")
	old, err := open(t.Context(), path, "management", func(ctx context.Context, db *sql.DB) error {
		if err := bootstrapBase(ctx, db); err != nil {
			return err
		}
		for _, migration := range []Migration{managementAuthMigration, managementInitializationMigration, proxyCredentialsMigration, managementOAuthMigration, managementAuditMigration} {
			if err := applyMigration(ctx, db, migration); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.DB().ExecContext(t.Context(), `INSERT INTO management_users(id,login,role,client_salt,credential,created_at,updated_at) VALUES('admin','admin','admin',randomblob(16),randomblob(32),1,1)`); err != nil {
		t.Fatal(err)
	}
	broken := trafficGroupsMigration
	broken.Statements = append(slices.Clone(broken.Statements), "INVALID SQL FOR INTERRUPTION TEST")
	if err := applyMigration(t.Context(), old.DB(), broken); err == nil {
		t.Fatal("failed migration reported success")
	}
	if schemaObjectExists(t, old.DB(), "traffic_groups") {
		t.Fatal("interrupted migration leaked partial schema")
	}
	if queryInt(t, old.DB(), `SELECT count(*) FROM migrate`) != 5 {
		t.Fatal("interrupted migration committed its marker")
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := OpenManagement(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := upgraded.DB().ExecContext(t.Context(), `INSERT INTO traffic_groups(id,name,description,created_at,updated_at) VALUES('finance','Finance','',1,1); INSERT INTO traffic_group_members(group_id,user_id) VALUES('finance','admin')`); err != nil {
		t.Fatal(err)
	}
	if _, err := upgraded.DB().ExecContext(t.Context(), `INSERT INTO traffic_group_members(group_id,user_id) VALUES('finance','missing')`); err == nil {
		t.Fatal("dangling member accepted")
	}
	if err := upgraded.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenManagement(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if queryInt(t, restarted.DB(), `SELECT count(*) FROM traffic_group_members WHERE user_id='admin' AND group_id='finance'`) != 1 {
		t.Fatal("restart lost membership")
	}
	if queryInt(t, restarted.DB(), `SELECT count(*) FROM management_users WHERE credential IS NOT NULL`) != 1 {
		t.Fatal("migration lost credentials")
	}
}

package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestProxyIdentityMigrationPreservesAccountsTokensAndSetup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "management.db")
	old, err := open(t.Context(), path, "management", func(ctx context.Context, db *sql.DB) error {
		if err := bootstrapBase(ctx, db); err != nil {
			return err
		}
		for _, migration := range []Migration{managementAuthMigration, managementInitializationMigration} {
			if err := applyMigration(ctx, db, migration); err != nil {
				return err
			}
		}
		_, err := db.ExecContext(ctx, `INSERT INTO management_users(id,login,role,client_salt,credential,created_at,updated_at) VALUES('admin','admin','admin',randomblob(16),'verifier',1,1),('reader','reader','read-only',randomblob(16),'verifier',1,1)`)
		if err != nil {
			return err
		}
		_, err = db.ExecContext(ctx, `INSERT INTO management_credentials(id,user_id,kind,verifier,prefix,scopes,generation,created_at) VALUES('token','admin','token',randomblob(32),'prefix','[]',1,1)`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = old.Close(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := OpenManagement(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	db := upgraded.DB()
	if queryInt(t, db, `SELECT count(*) FROM management_users`) != 2 || queryInt(t, db, `SELECT count(*) FROM management_credentials WHERE user_id='admin'`) != 1 || queryInt(t, db, `SELECT completed FROM management_initialization`) != 1 {
		t.Fatal("migration lost identities, tokens, or setup latch")
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE management_users SET role='none' WHERE id='reader'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE management_users SET role='none' WHERE id='admin'`); err == nil {
		t.Fatal("migration lost last-admin guard")
	}
	if _, err := db.ExecContext(t.Context(), `DELETE FROM management_users WHERE id='admin'`); err == nil {
		t.Fatal("migration lost last-admin delete guard")
	}
	if queryInt(t, db, `SELECT count(*) FROM pragma_foreign_key_check`) != 0 {
		t.Fatal("migration broke credential ownership")
	}
}

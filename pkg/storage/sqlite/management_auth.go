package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// OpenManagement uses the existing private-file, journal, shared connection and
// migration machinery with a separate schema. State/configuration snapshots can
// never contain these identities, and restoring one cannot replace an admin.
func OpenManagement(ctx context.Context, path string) (*Store, error) {
	return open(ctx, path, "management", func(ctx context.Context, db *sql.DB) error {
		if err := bootstrapBase(ctx, db); err != nil {
			return err
		}
		var name string
		err := db.QueryRowContext(ctx, `SELECT name FROM migrate WHERE version=1`).Scan(&name)
		if err == nil {
			if name != managementAuthMigration.Name {
				return fmt.Errorf("database is not a management identity store")
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		return applyMigration(ctx, db, managementAuthMigration)
	})
}

// Credentials deliberately live outside configBackupTables. A configuration
// restore must neither export authentication material nor replace local admins.
var managementAuthMigration = Migration{
	Version: 1,
	Name:    "management_identities",
	Statements: []string{
		`CREATE TABLE management_users (
			id TEXT PRIMARY KEY, login TEXT NOT NULL UNIQUE COLLATE NOCASE,
			role TEXT NOT NULL CHECK(role IN ('admin','read-only')),
			disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0,1)),
			client_salt BLOB NOT NULL, server_salt BLOB,
			client_kdf TEXT NOT NULL DEFAULT 'pbkdf2-sha256-v1' CHECK(client_kdf='pbkdf2-sha256-v1'),
			server_kdf TEXT NOT NULL DEFAULT 'argon2id-v1' CHECK(server_kdf='argon2id-v1'),
			credential BLOB, generation INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE management_credentials (
			id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES management_users(id) ON DELETE CASCADE,
			kind TEXT NOT NULL CHECK(kind IN ('token','session','enrollment')),
			verifier BLOB NOT NULL UNIQUE, prefix TEXT NOT NULL, scopes TEXT NOT NULL,
			generation INTEGER NOT NULL, created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
		)`,
		`CREATE INDEX management_credentials_owner ON management_credentials(user_id)`,
		`CREATE TABLE management_auth_setup (id INTEGER PRIMARY KEY CHECK(id=1), setup BLOB NOT NULL)`,
		`CREATE TABLE management_security_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at INTEGER NOT NULL,
			event TEXT NOT NULL, actor_id TEXT NOT NULL, subject_id TEXT NOT NULL
		)`,
		`CREATE TRIGGER management_last_admin_update BEFORE UPDATE OF disabled, role ON management_users
		WHEN OLD.role='admin' AND OLD.disabled=0 AND (NEW.role!='admin' OR NEW.disabled!=0)
		AND NOT EXISTS(SELECT 1 FROM management_users WHERE id!=OLD.id AND role='admin' AND disabled=0 AND credential IS NOT NULL)
		BEGIN SELECT RAISE(ABORT, 'last active administrator'); END`,
		`CREATE TRIGGER management_last_admin_delete BEFORE DELETE ON management_users
		WHEN OLD.role='admin' AND OLD.disabled=0
		AND NOT EXISTS(SELECT 1 FROM management_users WHERE id!=OLD.id AND role='admin' AND disabled=0 AND credential IS NOT NULL)
		BEGIN SELECT RAISE(ABORT, 'last active administrator'); END`,
	},
}

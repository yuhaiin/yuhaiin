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
		for _, migration := range []Migration{managementAuthMigration, managementInitializationMigration, proxyCredentialsMigration, managementOAuthMigration, managementAuditMigration, managementSSTPMigration} {
			var name string
			err := db.QueryRowContext(ctx, `SELECT name FROM migrate WHERE version=?`, migration.Version).Scan(&name)
			if err == nil {
				if name != migration.Name {
					return fmt.Errorf("database is not a management identity store")
				}
				continue
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if err := applyMigration(ctx, db, migration); err != nil {
				return err
			}
		}
		return nil
	})
}

// SSTP needs a password-equivalent NT hash for its MS-CHAPv2 challenge protocol.
// Existing credentials cannot be upgraded without the original one-time secret.
var managementSSTPMigration = Migration{Version: 6, Name: "sstp_proxy_verifiers", Statements: []string{
	`ALTER TABLE proxy_credentials ADD COLUMN sstp_nt_hash BLOB`,
}}

var managementAuditMigration = Migration{Version: 5, Name: "management_audit_context", Statements: []string{
	`ALTER TABLE management_security_events ADD COLUMN source TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE management_security_events ADD COLUMN request_method TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE management_security_events ADD COLUMN request_path TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE management_security_events ADD COLUMN credential_id TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE management_security_events ADD COLUMN result TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE management_security_events ADD COLUMN changes_json TEXT NOT NULL DEFAULT ''`,
}}

// The completion latch survives password resets and disabled accounts. Backfill
// from enrollment history as well as current credentials when upgrading v1.
var managementInitializationMigration = Migration{
	Version: 2,
	Name:    "management_initialization",
	Statements: []string{
		`CREATE TABLE management_initialization (
			id INTEGER PRIMARY KEY CHECK(id=1), completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0,1)),
			verifier BLOB, client_salt BLOB, expires_at INTEGER NOT NULL DEFAULT 0
		)`,
		`INSERT INTO management_initialization(id,completed) SELECT 1,
			EXISTS(SELECT 1 FROM management_users WHERE credential IS NOT NULL)
			OR EXISTS(SELECT 1 FROM management_security_events WHERE event IN ('user.enrolled','login.succeeded','user.credentials_reset'))`,
		`CREATE TRIGGER management_initialized_insert AFTER INSERT ON management_users WHEN NEW.credential IS NOT NULL
		BEGIN UPDATE management_initialization SET completed=1,verifier=NULL,client_salt=NULL,expires_at=0 WHERE id=1; END`,
		`CREATE TRIGGER management_initialized_update AFTER UPDATE OF credential ON management_users WHEN NEW.credential IS NOT NULL
		BEGIN UPDATE management_initialization SET completed=1,verifier=NULL,client_salt=NULL,expires_at=0 WHERE id=1; END`,
	},
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

// OAuth identities and application secrets share the private identity database,
// never configuration backups. Existing sessions acquire safe empty metadata.
var managementOAuthMigration = Migration{
	Version: 4,
	Name:    "management_oauth_sessions",
	Statements: []string{
		`ALTER TABLE management_credentials ADD COLUMN user_agent TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE management_credentials ADD COLUMN remote_addr TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE management_credentials ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE management_credentials ADD COLUMN auth_method TEXT NOT NULL DEFAULT 'password'`,
		`CREATE TABLE management_oauth_providers (
            provider TEXT PRIMARY KEY CHECK(provider IN ('github','google')),
            client_id TEXT NOT NULL, client_secret TEXT NOT NULL, redirect_url TEXT NOT NULL
        )`,
		`CREATE TABLE management_oauth_links (
            provider TEXT NOT NULL CHECK(provider IN ('github','google')), subject TEXT NOT NULL,
            user_id TEXT NOT NULL REFERENCES management_users(id) ON DELETE CASCADE,
            display_name TEXT NOT NULL, created_at INTEGER NOT NULL,
            PRIMARY KEY(provider,subject), UNIQUE(user_id,provider)
        )`,
	},
}

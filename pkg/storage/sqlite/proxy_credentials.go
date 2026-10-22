package sqlite

import "strings"

// Rebuild both identity tables together so v1/v2 databases accept proxy-only
// users without weakening the existing last-administrator constraints.
var proxyCredentialsMigration = func() Migration {
	statements := []string{
		`DROP TRIGGER management_last_admin_update`, `DROP TRIGGER management_last_admin_delete`,
		`DROP TRIGGER management_initialized_insert`, `DROP TRIGGER management_initialized_update`,
		`ALTER TABLE management_credentials RENAME TO management_credentials_previous`,
		`ALTER TABLE management_users RENAME TO management_users_previous`,
		strings.Replace(managementAuthMigration.Statements[0], "'admin','read-only'", "'admin','read-only','none'", 1),
		`INSERT INTO management_users SELECT * FROM management_users_previous`,
		managementAuthMigration.Statements[1],
		`INSERT INTO management_credentials SELECT * FROM management_credentials_previous`,
		`DROP TABLE management_credentials_previous`, `DROP TABLE management_users_previous`,
		managementAuthMigration.Statements[2],
		managementAuthMigration.Statements[5], managementAuthMigration.Statements[6],
		managementInitializationMigration.Statements[2], managementInitializationMigration.Statements[3],
		`CREATE TABLE proxy_credentials (
   id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES management_users(id) ON DELETE CASCADE,
   name TEXT NOT NULL, verifier BLOB NOT NULL UNIQUE, wire_verifier BLOB NOT NULL UNIQUE,
   generation INTEGER NOT NULL, inbounds TEXT NOT NULL, protocols TEXT NOT NULL,
   created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL DEFAULT 0,
   revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
  )`,
		`CREATE INDEX proxy_credentials_owner ON proxy_credentials(user_id)`,
		`CREATE TABLE upstream_credentials (
   id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL CHECK(type IN ('password','username-password')),
   username TEXT NOT NULL, password TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1
  )`,
	}
	return Migration{Version: 3, Name: "proxy_credentials", Statements: statements}
}()

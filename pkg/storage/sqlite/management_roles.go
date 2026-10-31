package sqlite

// Custom role assignments extend the protected built-in role column. Keeping
// that column and its triggers preserves local recovery and the last-admin
// invariant without rebuilding tables referenced by traffic identities.
var managementRolesMigration = Migration{Version: 11, Name: "management_roles", Statements: []string{
	`CREATE TABLE management_roles(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE COLLATE NOCASE,description TEXT NOT NULL,permissions TEXT NOT NULL CHECK(json_valid(permissions)),revision INTEGER NOT NULL CHECK(revision>0))`,
	`CREATE TABLE management_role_assignments(user_id TEXT PRIMARY KEY REFERENCES management_users(id) ON DELETE CASCADE,revision INTEGER NOT NULL CHECK(revision>0)) WITHOUT ROWID`,
	`CREATE TABLE management_user_roles(user_id TEXT NOT NULL REFERENCES management_users(id) ON DELETE CASCADE,role_id TEXT NOT NULL REFERENCES management_roles(id) ON DELETE RESTRICT,PRIMARY KEY(user_id,role_id)) WITHOUT ROWID`,
	`CREATE INDEX management_user_roles_role ON management_user_roles(role_id,user_id)`,
	`ALTER TABLE management_credentials ADD COLUMN enrollment_salt BLOB`,
}}

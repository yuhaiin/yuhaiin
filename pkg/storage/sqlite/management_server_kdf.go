package sqlite

// The legacy server_kdf column is pinned to 'argon2id-v1' by a CHECK constraint
// that SQLite cannot relax without rebuilding management_users, which many
// tables reference with ON DELETE CASCADE. password_kdf supersedes it; existing
// verifiers stay 'argon2id-v1' until the next successful login rehashes them.
var managementServerKDFMigration = Migration{Version: 16, Name: "management_server_kdf", Statements: []string{
	`ALTER TABLE management_users ADD COLUMN password_kdf TEXT NOT NULL DEFAULT 'argon2id-v1' CHECK(password_kdf IN ('argon2id-v1','argon2id-v2'))`,
}}

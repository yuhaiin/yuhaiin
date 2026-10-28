package sqlite

// Private managed HTTPS material shares the existing private configuration DB.
// None of these tables participates in configuration-only export. Full recovery
// snapshots include them as part of the coordinated SQLite file set.
var managedCertificatesMigration = Migration{Version: 24, Name: "managed_https_certificates", Statements: []string{
	`CREATE TABLE managed_certificates (
		id TEXT PRIMARY KEY,
		revision INTEGER NOT NULL CHECK(revision>0),
		config_json TEXT NOT NULL CHECK(json_valid(config_json)),
		status_json TEXT NOT NULL CHECK(json_valid(status_json)),
		lease_owner TEXT NOT NULL DEFAULT '',
		lease_until INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE TABLE managed_certificate_material (
		certificate_id TEXT PRIMARY KEY REFERENCES managed_certificates(id) ON DELETE CASCADE,
		certificate_pem BLOB NOT NULL,
		private_key_pem BLOB NOT NULL
	)`,
	`CREATE TABLE certificate_dns_providers (
		id TEXT PRIMARY KEY,
		revision INTEGER NOT NULL CHECK(revision>0),
		config_json TEXT NOT NULL CHECK(json_valid(config_json)),
		token BLOB NOT NULL
	)`,
	`CREATE TABLE certificate_acme_accounts (
		directory TEXT NOT NULL,
		email TEXT NOT NULL,
		private_key_pem BLOB NOT NULL,
		account_uri TEXT NOT NULL DEFAULT '',
		PRIMARY KEY(directory,email)
	)`,
	`CREATE TABLE certificate_references (
		kind TEXT NOT NULL CHECK(kind IN ('gateway','management')),
		owner_id TEXT NOT NULL,
		owner_name TEXT NOT NULL,
		certificate_id TEXT NOT NULL REFERENCES managed_certificates(id),
		PRIMARY KEY(kind,owner_id,certificate_id)
	)`,
	`CREATE INDEX certificate_references_target ON certificate_references(certificate_id)`,
	`CREATE TABLE certificate_dns_cleanup (
		id TEXT PRIMARY KEY,
		provider_id TEXT NOT NULL REFERENCES certificate_dns_providers(id),
		record_json TEXT NOT NULL CHECK(json_valid(record_json)),
		created_at INTEGER NOT NULL
	)`,
}}

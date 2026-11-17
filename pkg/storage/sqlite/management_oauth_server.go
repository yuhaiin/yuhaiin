package sqlite

// The OAuth 2.1 Authorization Server keeps its state in the private identity
// database next to users, sessions and API tokens, never in configuration
// backups. Access and refresh tokens are ordinary management credentials of
// two new kinds, bound to an authorization grant; the table is rebuilt only
// to widen its kind constraint. Every existing column and row is preserved.
var managementOAuthServerMigration = Migration{Version: 17, Name: "management_oauth_server", Statements: []string{
	`CREATE TABLE management_oauth_server (
		id INTEGER PRIMARY KEY CHECK(id=1),
		enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
		issuer TEXT NOT NULL DEFAULT '',
		dynamic_registration INTEGER NOT NULL DEFAULT 1 CHECK(dynamic_registration IN (0,1)),
		disabled_resources TEXT NOT NULL DEFAULT '[]',
		access_token_ttl INTEGER NOT NULL DEFAULT 900,
		refresh_token_ttl INTEGER NOT NULL DEFAULT 1209600,
		grant_ttl INTEGER NOT NULL DEFAULT 7776000,
		revision INTEGER NOT NULL DEFAULT 1
	)`,
	`INSERT INTO management_oauth_server(id) VALUES(1)`,
	`CREATE TABLE management_oauth_clients (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		client_type TEXT NOT NULL CHECK(client_type IN ('public','confidential')),
		registration TEXT NOT NULL CHECK(registration IN ('manual','dynamic')),
		redirect_uris TEXT NOT NULL,
		token_endpoint_auth_method TEXT NOT NULL CHECK(token_endpoint_auth_method IN ('none','client_secret_basic','client_secret_post')),
		secret_hash BLOB,
		grant_types TEXT NOT NULL,
		scopes TEXT NOT NULL,
		resources TEXT NOT NULL,
		client_uri TEXT NOT NULL DEFAULT '',
		created_by TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0,1)),
		CHECK((client_type='public') = (token_endpoint_auth_method='none')),
		CHECK((client_type='public') = (secret_hash IS NULL))
	)`,
	`CREATE TABLE management_oauth_grants (
		id TEXT PRIMARY KEY,
		client_id TEXT NOT NULL REFERENCES management_oauth_clients(id) ON DELETE CASCADE,
		user_id TEXT NOT NULL REFERENCES management_users(id) ON DELETE CASCADE,
		resource TEXT NOT NULL,
		scopes TEXT NOT NULL,
		generation INTEGER NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		last_used_at INTEGER NOT NULL DEFAULT 0,
		revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
		revoked_reason TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX management_oauth_grants_user ON management_oauth_grants(user_id)`,
	`CREATE INDEX management_oauth_grants_client ON management_oauth_grants(client_id)`,
	`CREATE TABLE management_oauth_codes (
		verifier BLOB PRIMARY KEY,
		client_id TEXT NOT NULL REFERENCES management_oauth_clients(id) ON DELETE CASCADE,
		user_id TEXT NOT NULL REFERENCES management_users(id) ON DELETE CASCADE,
		redirect_uri TEXT NOT NULL,
		redirect_uri_required INTEGER NOT NULL CHECK(redirect_uri_required IN (0,1)),
		code_challenge TEXT NOT NULL,
		resource TEXT NOT NULL,
		scopes TEXT NOT NULL,
		generation INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		consumed_at INTEGER NOT NULL DEFAULT 0,
		grant_id TEXT REFERENCES management_oauth_grants(id) ON DELETE SET NULL
	)`,
	`ALTER TABLE management_credentials RENAME TO management_credentials_previous`,
	`CREATE TABLE management_credentials (
		id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES management_users(id) ON DELETE CASCADE,
		kind TEXT NOT NULL CHECK(kind IN ('token','session','enrollment','oauth_access','oauth_refresh')),
		verifier BLOB NOT NULL UNIQUE, prefix TEXT NOT NULL, scopes TEXT NOT NULL,
		generation INTEGER NOT NULL, created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
		user_agent TEXT NOT NULL DEFAULT '', remote_addr TEXT NOT NULL DEFAULT '',
		last_seen INTEGER NOT NULL DEFAULT 0, auth_method TEXT NOT NULL DEFAULT 'password',
		enrollment_salt BLOB, name TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
		grant_id TEXT REFERENCES management_oauth_grants(id) ON DELETE CASCADE,
		CHECK((kind IN ('oauth_access','oauth_refresh')) = (grant_id IS NOT NULL))
	)`,
	`INSERT INTO management_credentials(id,user_id,kind,verifier,prefix,scopes,generation,created_at,expires_at,revoked,user_agent,remote_addr,last_seen,auth_method,enrollment_salt,name,note)
		SELECT id,user_id,kind,verifier,prefix,scopes,generation,created_at,expires_at,revoked,user_agent,remote_addr,last_seen,auth_method,enrollment_salt,name,note FROM management_credentials_previous`,
	`DROP TABLE management_credentials_previous`,
	`CREATE INDEX management_credentials_owner ON management_credentials(user_id)`,
	`CREATE INDEX management_credentials_grant ON management_credentials(grant_id)`,
}}

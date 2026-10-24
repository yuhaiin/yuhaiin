package sqlite

// Generic OIDC stays in the existing private identity store. Existing OAuth
// bindings survive unchanged; no configuration/backup database gains identities.
var managementOIDCMigration = Migration{Version: 10, Name: "management_oidc", Statements: []string{
	`CREATE TABLE management_oauth_providers_v2 (
 provider TEXT PRIMARY KEY, client_id TEXT NOT NULL, client_secret TEXT NOT NULL,
 redirect_url TEXT NOT NULL, issuer TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '',
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)), revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),
 CHECK(provider IN ('github','google') OR (substr(provider,1,5)='oidc-' AND length(provider)=41 AND issuer<>'')))`,
	`INSERT INTO management_oauth_providers_v2(provider,client_id,client_secret,redirect_url,name) SELECT provider,client_id,client_secret,redirect_url,provider FROM management_oauth_providers`,
	`DROP TABLE management_oauth_providers`,
	`ALTER TABLE management_oauth_providers_v2 RENAME TO management_oauth_providers`,
	`CREATE UNIQUE INDEX management_oidc_issuers ON management_oauth_providers(issuer) WHERE issuer<>''`,
	`CREATE TABLE management_oauth_links_v2 (
 provider TEXT NOT NULL, issuer TEXT NOT NULL DEFAULT '', subject TEXT NOT NULL,
 user_id TEXT NOT NULL REFERENCES management_users(id) ON DELETE CASCADE,
 display_name TEXT NOT NULL, created_at INTEGER NOT NULL,
 PRIMARY KEY(provider,subject), UNIQUE(user_id,provider))`,
	`INSERT INTO management_oauth_links_v2(provider,subject,user_id,display_name,created_at,issuer) SELECT provider,subject,user_id,display_name,created_at,CASE provider WHEN 'google' THEN 'https://accounts.google.com' ELSE 'https://github.com' END FROM management_oauth_links`,
	`DROP TABLE management_oauth_links`,
	`ALTER TABLE management_oauth_links_v2 RENAME TO management_oauth_links`,
	`CREATE UNIQUE INDEX management_oidc_subjects ON management_oauth_links(issuer,subject) WHERE issuer<>''`,
}}

package sqlite

const usageDimensionsSQL = `
 user_id TEXT NOT NULL, credential_id TEXT NOT NULL, inbound_id TEXT NOT NULL,
 node_id TEXT NOT NULL, protocol TEXT NOT NULL,
 inbound_name TEXT NOT NULL, node_name TEXT NOT NULL,
 upload_bytes INTEGER NOT NULL DEFAULT 0, download_bytes INTEGER NOT NULL DEFAULT 0,
 opened INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0,
 session_millis INTEGER NOT NULL DEFAULT 0,
 first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL`

var userUsageMigration = Migration{Version: 17, Name: "user_usage", Statements: []string{
	`CREATE TABLE user_usage_settings (id INTEGER PRIMARY KEY CHECK(id=1), options_json TEXT NOT NULL CHECK(json_valid(options_json)))`,
	`CREATE TABLE user_usage_totals (` + usageDimensionsSQL + `,
 PRIMARY KEY(user_id,credential_id,inbound_id,node_id,protocol)) WITHOUT ROWID`,
	`CREATE TABLE user_usage_buckets (
 period TEXT NOT NULL CHECK(period IN ('hour','day')), bucket INTEGER NOT NULL,` + usageDimensionsSQL + `,
 PRIMARY KEY(period,bucket,user_id,credential_id,inbound_id,node_id,protocol)) WITHOUT ROWID`,
	`CREATE INDEX user_usage_buckets_owner ON user_usage_buckets(user_id,period,bucket)`,
	`CREATE TABLE user_usage_activity (
 user_id TEXT NOT NULL, minute INTEGER NOT NULL, PRIMARY KEY(user_id,minute)) WITHOUT ROWID`,
	`CREATE TABLE user_usage_users (
 user_id TEXT PRIMARY KEY, active_minutes INTEGER NOT NULL DEFAULT 0,
 peak_tcp INTEGER NOT NULL DEFAULT 0, peak_udp INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID`,
	`CREATE TABLE user_usage_audit (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL, credential_id TEXT NOT NULL,
 inbound_id TEXT NOT NULL, node_id TEXT NOT NULL, protocol TEXT NOT NULL,
 source TEXT NOT NULL, target TEXT NOT NULL, result TEXT NOT NULL,
 started_at INTEGER NOT NULL, checkpoint_at INTEGER NOT NULL,
 data_json TEXT NOT NULL CHECK(json_valid(data_json)))`,
	`CREATE INDEX user_usage_audit_owner ON user_usage_audit(user_id,started_at DESC,id DESC)`,
	`CREATE INDEX user_usage_audit_time ON user_usage_audit(checkpoint_at)`,
	`CREATE INDEX user_usage_audit_recent ON user_usage_audit(started_at DESC,id DESC) WHERE result!='active'`,
	`CREATE TABLE user_usage_flush (id INTEGER PRIMARY KEY CHECK(id=1), batch_id TEXT NOT NULL)`,
}}

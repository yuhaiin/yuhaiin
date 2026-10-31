package sqlite

// Identity resource policy and quota credits share the private management DB.
// Ordinary configuration restore must not roll back authoritative byte usage.
var resourceGovernanceMigration = Migration{Version: 10, Name: "resource_governance", Statements: []string{
	`CREATE TABLE resource_config(id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, data TEXT NOT NULL CHECK(json_valid(data)))`,
	`CREATE TABLE resource_groups(group_id TEXT PRIMARY KEY REFERENCES traffic_groups(id)) WITHOUT ROWID`,
	`CREATE TRIGGER resource_group_delete BEFORE UPDATE OF deleted ON traffic_groups
	 WHEN NEW.deleted=1 AND EXISTS(SELECT 1 FROM resource_groups WHERE group_id=OLD.id)
	 BEGIN SELECT RAISE(ABORT, 'group is referenced by resource policy'); END`,
	`CREATE TABLE quota_definitions(
	 scope TEXT NOT NULL CHECK(scope IN ('user','group','credential')), scope_id TEXT NOT NULL,
	 quota_id TEXT NOT NULL, period TEXT NOT NULL CHECK(period IN ('daily','monthly','lifetime')), owner_user_id TEXT NOT NULL,
	 PRIMARY KEY(scope,scope_id,quota_id), UNIQUE(scope,scope_id,quota_id,period)) WITHOUT ROWID`,
	`CREATE TABLE quota_windows(
	 scope TEXT NOT NULL, scope_id TEXT NOT NULL, quota_id TEXT NOT NULL, period TEXT NOT NULL, starts_at INTEGER NOT NULL,
	 measured_up INTEGER NOT NULL CHECK(measured_up>=0), measured_down INTEGER NOT NULL CHECK(measured_down>=0), measured_combined INTEGER NOT NULL CHECK(measured_combined>=0),
	 charged_up INTEGER NOT NULL CHECK(charged_up>=measured_up), charged_down INTEGER NOT NULL CHECK(charged_down>=measured_down), charged_combined INTEGER NOT NULL CHECK(charged_combined>=measured_combined),
	 alerts_low INTEGER NOT NULL, alerts_high INTEGER NOT NULL, denied INTEGER NOT NULL CHECK(denied>=0),
	 PRIMARY KEY(scope,scope_id,quota_id,period,starts_at),
	 FOREIGN KEY(scope,scope_id,quota_id,period) REFERENCES quota_definitions(scope,scope_id,quota_id,period)) WITHOUT ROWID`,
	`CREATE INDEX quota_windows_expiry ON quota_windows(period,starts_at)`,
	`CREATE TABLE quota_alerts(
	 id INTEGER PRIMARY KEY AUTOINCREMENT, owner_user_id TEXT NOT NULL,
	 scope TEXT NOT NULL, scope_id TEXT NOT NULL, quota_id TEXT NOT NULL, period TEXT NOT NULL,
	 starts_at INTEGER NOT NULL, occurred_at INTEGER NOT NULL, threshold INTEGER NOT NULL CHECK(threshold BETWEEN 1 AND 100),
	 UNIQUE(scope,scope_id,quota_id,period,starts_at,threshold))`,
	`CREATE INDEX quota_alerts_owner ON quota_alerts(owner_user_id,id DESC)`,
	`CREATE INDEX quota_alerts_scope ON quota_alerts(scope,scope_id,id DESC)`,
}}

package sqlite

var managementSecurityAuditMigration = Migration{Version: 11, Name: "management_security_audit", Statements: []string{
	`ALTER TABLE management_security_events ADD COLUMN auth_method TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE management_security_events ADD COLUMN policy_revision TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE management_security_events ADD COLUMN reason TEXT NOT NULL DEFAULT ''`,
	`CREATE INDEX management_security_events_time ON management_security_events(occurred_at)`,
	`CREATE INDEX management_security_events_actor ON management_security_events(actor_id,id)`,
	`CREATE INDEX management_security_events_resource ON management_security_events(subject_id,id)`,
	`CREATE TABLE management_audit_settings (
 id INTEGER PRIMARY KEY CHECK(id=1), instance_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0),
 max_events INTEGER NOT NULL CHECK(max_events BETWEEN 1000 AND 100000), max_age_days INTEGER NOT NULL CHECK(max_age_days BETWEEN 0 AND 3650),
 forward_enabled INTEGER NOT NULL CHECK(forward_enabled IN (0,1)), forward_transport TEXT NOT NULL CHECK(forward_transport IN ('https','syslog-tls')),
 forward_endpoint TEXT NOT NULL, forward_token TEXT NOT NULL,
 outbox_limit INTEGER NOT NULL CHECK(outbox_limit BETWEEN 64 AND 16384),retained_events INTEGER NOT NULL DEFAULT 0 CHECK(retained_events>=0))`,
	`INSERT INTO management_audit_settings VALUES(1,lower(hex(randomblob(16))),1,10000,90,0,'https','','',4096,0)`,
	`UPDATE management_audit_settings SET retained_events=(SELECT count(*) FROM management_security_events) WHERE id=1`,
	`CREATE TRIGGER management_audit_row_insert AFTER INSERT ON management_security_events BEGIN UPDATE management_audit_settings SET retained_events=retained_events+1 WHERE id=1; END`,
	`CREATE TRIGGER management_audit_row_delete AFTER DELETE ON management_security_events BEGIN UPDATE management_audit_settings SET retained_events=retained_events-1 WHERE id=1; END`,
	`CREATE TABLE management_audit_delivery (
 id INTEGER PRIMARY KEY CHECK(id=1), dropped INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0,
 delivered INTEGER NOT NULL DEFAULT 0, last_success INTEGER NOT NULL DEFAULT 0, last_failure INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '')`,
	`INSERT INTO management_audit_delivery(id) VALUES(1)`,
	// The outbox owns a bounded copy. Local ledger retention cannot silently erase
	// an undelivered item; its own age/overflow policy has persisted drop counters.
	`CREATE TABLE management_audit_outbox(event_id INTEGER PRIMARY KEY,payload TEXT NOT NULL,created_at INTEGER NOT NULL)`,
	`CREATE INDEX management_audit_outbox_time ON management_audit_outbox(created_at)`,
}}

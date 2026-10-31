package sqlite

// Traffic authorization remains in the private management database. A config
// backup cannot silently replace the authorization protecting its own restore.
var trafficAccessMigration = Migration{Version: 9, Name: "traffic_access", Statements: []string{
	`CREATE TABLE traffic_access_config(id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE traffic_access_groups(group_id TEXT PRIMARY KEY REFERENCES traffic_groups(id)) WITHOUT ROWID`,
	`CREATE TRIGGER traffic_access_group_delete BEFORE UPDATE OF deleted ON traffic_groups
	WHEN NEW.deleted=1 AND EXISTS(SELECT 1 FROM traffic_access_groups WHERE group_id=OLD.id)
	BEGIN SELECT RAISE(ABORT, 'group is referenced by access policy'); END`,
}}

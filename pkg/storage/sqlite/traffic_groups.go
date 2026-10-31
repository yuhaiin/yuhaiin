package sqlite

var trafficGroupsMigration = Migration{Version: 8, Name: "traffic_groups", Statements: []string{
	`CREATE TABLE traffic_groups (
		id TEXT PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE,
		description TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1,
		deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1)),
		created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
	)`,
	`CREATE UNIQUE INDEX traffic_groups_name ON traffic_groups(name) WHERE deleted=0`,
	`CREATE TABLE traffic_group_members (
		group_id TEXT NOT NULL REFERENCES traffic_groups(id) ON DELETE CASCADE,
		user_id TEXT NOT NULL REFERENCES management_users(id) ON DELETE CASCADE,
		PRIMARY KEY(group_id,user_id)
	) WITHOUT ROWID`,
	`CREATE INDEX traffic_group_members_user ON traffic_group_members(user_id,group_id)`,
	`CREATE TRIGGER traffic_groups_retired_member BEFORE INSERT ON traffic_group_members
	WHEN EXISTS(SELECT 1 FROM traffic_groups WHERE id=NEW.group_id AND deleted=1)
	BEGIN SELECT RAISE(ABORT, 'group is deleted'); END`,
	`CREATE TRIGGER traffic_groups_user_delete BEFORE DELETE ON management_users
	BEGIN UPDATE traffic_groups SET revision=revision+1,updated_at=unixepoch()
		WHERE id IN (SELECT group_id FROM traffic_group_members WHERE user_id=OLD.id); END`,
}}

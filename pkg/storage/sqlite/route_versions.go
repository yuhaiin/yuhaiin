package sqlite

import (
	"context"
	"database/sql"
	"fmt"
)

func addRouteConfigurationVersions(ctx context.Context, tx *sql.Tx) error {
	for _, statement := range []string{
		`ALTER TABLE route_settings ADD COLUMN revision INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE route_settings ADD COLUMN default_mode TEXT NOT NULL DEFAULT 'proxy'`,
		`ALTER TABLE route_settings ADD COLUMN default_target_json TEXT NOT NULL DEFAULT '{"type":"default"}' CHECK(json_valid(default_target_json))`,
		`CREATE TABLE route_configuration_state(id INTEGER PRIMARY KEY CHECK(id = 1), saved_revision INTEGER NOT NULL, applied_revision INTEGER NOT NULL,
		applied_rules_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(applied_rules_json)), applied_config_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(applied_config_json)))`,
		`INSERT INTO route_configuration_state(id, saved_revision, applied_revision) VALUES(1, 1, 0)`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	for _, table := range []string{"route_rules_v2", "route_lists_v2", "route_settings", "settings_kv"} {
		for _, operation := range []string{"INSERT", "UPDATE", "DELETE"} {
			when := ""
			if table == "settings_kv" {
				row := "NEW"
				if operation == "DELETE" {
					row = "OLD"
				}
				when = " WHEN " + row + ".section = 'route_extra'"
			}
			statement := fmt.Sprintf(`CREATE TRIGGER route_revision_%s_%s AFTER %s ON %s%s
			BEGIN UPDATE route_configuration_state SET saved_revision = saved_revision + 1 WHERE id = 1; END`, table, operation, operation, table, when)
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
	}
	return nil
}

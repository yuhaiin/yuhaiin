package sqlite

import "github.com/Asutorufa/yuhaiin/pkg/security/configchange"

var configurationChangesMigration = Migration{Version: 18, Name: "configuration_changes", Statements: configchange.SchemaStatements}
var managementConfigurationChangesMigration = Migration{Version: 12, Name: "management_configuration_changes", Statements: append([]string{
	// Provider revisions cannot repeat after deletion/recreation: an in-flight
	// verified flow from an earlier configuration must never regain validity.
	`CREATE TABLE management_oauth_revisions(provider TEXT PRIMARY KEY,revision INTEGER NOT NULL CHECK(revision>0))`,
	`INSERT INTO management_oauth_revisions(provider,revision) SELECT provider,revision FROM management_oauth_providers`,
}, configchange.SchemaStatements...)}

package snapshot

// These tables contain runtime data which changes frequently but is not needed
// to restore the user's proxy configuration. Keeping their schemas in the
// backup preserves direct state.db restore compatibility while avoiding the
// repeated upload of traffic and connection history.
var backupRuntimeTables = []string{
	"statistics_kv",
	"traffic_hourly",
	"connection_sessions",
	"connection_history",
	"failed_connection_history",
	"fakeip_entries",
	"fakeip_cursors",
	"traffic_dimension_hourly",
	"traffic_dimension_daily",
	"failure_dimension_hourly",
	"failure_dimension_daily",
	"telemetry_dimension_values",
	"backup_recovery_history",
	"backup_recovery_imports",
}

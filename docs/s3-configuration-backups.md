# S3 configuration backups

Yuhaiin stores its configuration and local operational history in SQLite
(`state.db`). S3 backups are **configuration backups**, not full archives of
the local database.

## Included data

The snapshot retains the database schema, configuration, route and DNS
settings, nodes, inbounds, gateway configuration and CA, subscriptions, backup
configuration, and user-usage retention settings. Restoring the snapshot can
therefore open the existing database format with its original indexes and
migrations.

## Excluded data

The backup snapshot removes rows from transient and high-churn runtime tables,
including:

- Connection/session history, failed connections, traffic and telemetry
  dimensions, and FakeIP mappings/counters.
- User usage totals, time buckets, activity, peaks, and connection audit logs
  (`user_usage_audit`). Only `user_usage_settings` is retained.
- Outbound node observability, gateway request counters, and inbound counters.

The local `state.db` is **not modified**. Historical usage and audit records
remain available locally under the configured retention policy. If you need to
preserve these records for compliance or disaster recovery, use a separate,
secure full-database backup. Configuration backups are not substitutes for
audit retention.

A configuration backup is produced using SQLite `VACUUM INTO` to a temporary
file. The excluded tables are cleared in that copy and the copy is compacted
before upload. If the resulting snapshot and S3 destination settings have not
changed, the upload is skipped. The same R2/S3 object is overwritten on an
actual configuration change: this is not an incremental or versioned backup.

For safety, migrations that introduce new tables must classify those tables
as configuration or runtime. An unclassified table causes a backup error
instead of silently uploading potentially sensitive new runtime data.

## Diagnosing unexpected upload traffic

Use SQLite's `dbstat` virtual table to inspect the space occupied by tables
and indexes in the local database:

```sql
SELECT name, ROUND(SUM(pgsize) / 1048576.0, 2) AS size_mb
FROM dbstat
GROUP BY name
ORDER BY SUM(pgsize) DESC;
```

A large local audit table is expected when auditing many connections, but it
should no longer inflate S3 configuration snapshots. If uploads continue
without configuration changes, inspect backup logs and verify that the
running build contains the latest backup table classification. Do not delete
live SQLite WAL/SHM files to reclaim space.

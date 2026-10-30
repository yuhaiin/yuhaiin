# S3 configuration backups

Yuhaiin stores its configuration and local operational history in SQLite
(`state.db`). The legacy S3 object is a configuration snapshot, not a full
disaster-recovery archive. It is unencrypted; use protected transport and
storage, and use the encrypted full backup for deployment identity and history.

## Included data

The snapshot retains the database schema, migrations, DNS and route settings,
route activation state, nodes, inbounds, inbound traffic-control configuration,
Gateway configuration and user-usage retention options. SQLite's node search
index is rebuilt from the sanitized snapshot. Source SQLite and its live
WAL data are never modified.

Recognized node and inbound credentials are removed; affected endpoints are
disabled. ShadowsocksR protocol and obfuscation parameters are removed because
they can contain a user key or custom HTTP headers. HTTP Mock payloads are
removed because they can contain arbitrary sensitive bytes. Subscription links
are omitted, while publish passwords, paths and
node lists are removed. Gateway header and query values and URL userinfo,
queries and fragments are removed, and relevant policies, filters and Gateways
are disabled. Recreate the omitted links and
review affected entries after import. Routes targeting a Gateway disabled by
this sanitization reject connections until it is explicitly re-enabled; import
these snapshots only into a version supporting `rejectWhenDisabled`, because
older versions cannot enforce that protection. S3 access keys, managed site and
ACME keys, DNS provider tokens and the Gateway CA are omitted. Restore of a
legacy S3 snapshot retains the target's own S3 and recovery settings.
Stored route-list and GeoIP refresh errors are omitted because they can include
credential-bearing URLs; route sources and refresh configuration are retained.
Guarded JSON exports use format version 2, which older JSON importers reject;
the legacy S3 SQLite format has no equivalent version gate.

Current-format Node and Inbound documents with unrecognized fields cause the
snapshot to fail before upload, except recognized legacy credential aliases
whose values have already been cleared; upgrade to a compatible version or remove the
unsupported fields before retrying. Legacy endpoint documents retain their
historical compatibility behavior. The sanitizer cannot identify every secret
in legacy custom data or opaque URL paths.
Protect all configuration snapshots. Previously uploaded objects are not
rewritten or removed and may still contain secrets excluded by newer versions.

## Excluded data

The snapshot removes transient and high-churn runtime data, including:

- Connection and session history, traffic and telemetry, and FakeIP state.
- User usage totals, time buckets, activity, peaks and audit logs.
- Outbound observations, Gateway and inbound request counters.
- Recovery history, managed certificate material and device identity data.

The original database retains its local history under its own retention policy.
If this data is needed for disaster recovery, use the encrypted full backup with
its history option; a configuration snapshot is not an audit archive.

A snapshot uses SQLite `VACUUM INTO` a private temporary file, sanitizes the
copy and compacts it before upload. Stable serialization and normalized runtime
bookkeeping allow unchanged configuration and destination settings to skip
upload. The existing S3 object is overwritten when the configuration changes;
this is not an incremental or versioned backup. New database tables must be
explicitly classified as configuration or excluded state. An unknown table or
unsupported virtual index fails the backup before upload.

## Diagnosing unexpected upload traffic

SQLite's `dbstat` virtual table can identify large local tables:

```sql
SELECT name, ROUND(SUM(pgsize) / 1048576.0, 2) AS size_mb
FROM dbstat
GROUP BY name
ORDER BY SUM(pgsize) DESC;
```

A large local audit table need not inflate configuration snapshots. Check the
backup status and running version if uploads recur without configuration
changes. Do not delete live SQLite WAL/SHM files to reclaim space.

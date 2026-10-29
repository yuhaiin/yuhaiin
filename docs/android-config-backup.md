# Android configuration backup and native status

The Android core uses local single-user management without the optional
`managementauth` HTTP middleware. No account database or first-run setup code is
created. The bundled Web UI detects local mode and opens directly; remote peers
still cannot use management APIs, including when the HTTP listener binds to LAN.

The Android JNI bridge exports `ExportConfig`, `ValidateConfig`, `ImportConfig`,
`App.NativeStatus` and `App.CheckHealth`. These APIs operate without a running Web
Dashboard. Android must set `SetConfigLockPath` to a shared path under its private
`no_backup` directory; emulated external storage does not support the lifecycle
file lock. Starting the core and importing configuration hold the same exclusive
lock, including across Android processes. A running core rejects imports.

Configuration exports are UTF-8 JSON with `format: "yuhaiin-config"`, `version: 1`,
a UTC `createdAt`, and `tables`. Each table contains its ordered `columns` and
`rows`; each cell is a JSON string, signed integer or null. Strings containing
configuration JSON are preserved as strings. Integer counters/timestamps are
never decoded through floating point. All configuration tables must be present,
including empty ones; column names and order must match the supported local
schema. A future or incompatible version is rejected rather than partially
restored. The reader and writer limit files to 32 MiB.

The table allowlist in `pkg/storage/sqlite/config_backup.go` includes native and
legacy configuration, Android preferences, nodes, publish settings, DNS, inbounds,
routing rules/lists/registries and backup settings. Only the selected TCP/UDP node
IDs are exported from metadata. Runtime counters, traffic/history, fake IP data,
migration markers and schemas are excluded. Android installer/document IDs and
session summaries live outside these tables. Recognized node/inbound credentials
are removed; affected nodes/listeners are disabled and affected legacy nodes are
deselected. S3 access and secret keys are omitted, and S3 backup, automatic
recovery and local-point cleanup consent are disabled in the exported settings.
Configure credentials and explicitly enable affected entries after importing.
Subscription links must be recreated, and publish paths, passwords and node
lists reconfigured; they are omitted to avoid exposing access credentials or
making a previously protected publication accessible without a password.
Gateway request/response headers, rewritten queries, header/query condition
values and credentials in Gateway URL userinfo, queries and fragments are removed;
affected policies, filters and Gateways must be reviewed and enabled
again. Routes selecting an affected disabled Gateway reject connections until
it is enabled. Older versions do not understand this guard and must not import
these snapshots. Guarded JSON exports use format version 2 so older JSON
importers reject them; the legacy S3 SQLite format lacks that version gate.
Import replaces existing subscription links with the exported empty set.
Exports remain plaintext and opaque URL paths, custom data or unknown fields may
contain secrets; Android explains this before export or sharing.

Exports read one transactionally consistent snapshot. Validation performs a
restore transaction and rolls it back, checking SQL constraints before Android
asks to disconnect. Imports delete and reinsert only allowlisted configuration
in one transaction, preserving the database inode, open preference handles and
local runtime data. Every failure rolls back. The VPN must be stopped first and
restarted after import to reload runtime state. Runtime TUN parameters are
rewritten from Android's newly established descriptor before the next startup.

`NativeStatus` returns selected node IDs/names (without chains or credentials),
start time, elapsed session seconds and `SessionSummary` from the existing
connection monitor. Session upload/download and opened/failed counts reset with
the runtime; active counts are sampled from its connection registry. Lifetime
traffic totals retain the existing persistence behavior. These are core-accounted
bytes, not Android device-wide network usage.

`CheckHealth` probes the selected TCP node using the existing HTTP latency test
and the UDP node using the DNS latency test. Probes run concurrently, outside the
core lifecycle mutex, and retain their existing bounded timeouts. Responses
include node IDs, success, latency, failure detail and the completion time.
Missing selections are absent rather than implicitly healthy. Android rejects
stale results after disconnect, reconnection, selection or network changes, and
refreshes on those changes, every minute and on manual request. Results describe
reachability of the default nodes to the probe targets, not all tagged routes.

Validation:

- `go test ./cmd/android ./pkg/storage/sqlite ./pkg/statistics`
- Build the matching JNI AAR with `make yuhaiin_android_aar` before Android Gradle.
- Android `BackupStatusTest` exercises real JNI/file-provider export, preview,
  atomic restore through an already-open preference handle, running-core import
  rejection and status/health/final-summary transfer over Binder.

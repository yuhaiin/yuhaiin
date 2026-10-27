# Software update history and rollback

The built-in updater keeps **the two most recently replaced executable files**. Root-owned Linux systemd installations can pair an update with the existing encrypted full-backup owner and independently supervise real startup readiness. Other installed platforms retain schema-checked executable updates only after an administrator explicitly disables automatic recovery protection; use reviewed offline recovery for database changes on those hosts.

## Storage

Snapshots are stored under the configured yuhaiin data directory:

```text
<data-dir>/
  update/
    versions/
      <sha256>.bin
      <sha256>.json
```

The JSON sidecar records the version, commit, SHA-256 ID, byte size, and snapshot timestamp. The archive directory is private to the service account. When restoring a version, the backend validates its ID and checks the binary's SHA-256 again before staging it next to the installed executable.

Each successful binary replacement archives the outgoing executable, removes the newly active binary from the history if it was previously archived, then keeps only the two newest remaining entries. A failed update does not prune the history. The transient `<executable>.update-backup` still protects the replacement operation itself.

## Web UI

Open **About → Software Update → Previous versions**. Select **Restore** for a history entry and confirm. The page requires maintenance/manual-recovery acknowledgement and follows the same compatibility and recovery protection as an ordinary update.

Only the **executable** is restored. Existing configuration, SQLite databases, and any migrations are not reverted. A binary downgrade may not be compatible with newer data.

The reliability branch now checks each configuration/management database's
known contiguous migration history, names and metadata version before bootstrap
writes or journal-mode changes. A future, foreign or incomplete schema is
rejected with an incompatibility error instead of silently skipping unknown
versions or applying configuration migrations to an identity database. Known
older prefixes still follow the existing transactional migrations; an empty
database or interrupted empty base bootstrap can initialize normally.

This startup guard does not establish that an arbitrary archived old binary is
safe: older binaries can lack the guard. Updater compatibility negotiation and protected pre-update recovery points are described below. Schema changes are not assumed reversible. Use a matching binary and verified database recovery point when
a migration is incompatible; executable history alone does not reverse it.

The [offline disaster-recovery CLI](recovery-archive.md) now verifies, previews
and activates a complete encrypted snapshot using a durable rollback journal.
Use its explicit original-instance or clone decision and startup instructions
when restoring databases/keys is necessary. It requires stopped writers and a
reviewed matching binary/schema. Protected updates now create these points through
the same collector on supported Linux services. File activation reports awaiting_startup until the
actual restored service passes its startup checks.

## Protected update and offline recovery

1. Open **Backup → Full disaster recovery backup**. Configure the external public
   age recipient, enable maintenance consent, save, and keep the private identity
   outside the deployment/archive. `protectUpdates` defaults to true, including
   when absent from existing settings. The periodic-backup toggle is independent.
2. On **About → Software Update**, review schema versions and recovery readiness.
   A supported, configured service may install a `migration_required` target.
   Explicitly accept connection interruption and confirm possession of the external
   key/offline access. Binary-only downgrade still requires compatible catalogs.
3. The shared maintenance lease excludes competing capture, Web restore, offline
   mutation and updates. A versioned private `.update-operation.json` persists the
   source/target manifests, executable paths, operation UUID and backup identities.
   The helper stops the installed service, captures the existing coherent encrypted
   full inventory (including history), verifies archive completion, preserves source
   executable/history/schema, rechecks the target, and only then swaps binaries.
4. `starting` is durable **before** service start. The target verifies its executable
   against the journal before opening stores. Database/inbound/Gateway readiness
   and the pinned local management listener must pass before it writes a receipt.
   The independent helper verifies that receipt's PID is the installed service's
   MainPID and independently probes the exact local listener twice, pinning its
   public TLS leaf with a short quiet period before committing. Existing connections are interrupted by this explicitly
   confirmed service restart; helper launch is never reported as success.

The required point is local encrypted storage. A configured S3 upload resumes
through the ordinary governed proxy after service recovery; remote durability is
not claimed until the normal size/SHA-256 readback succeeds. A target failure can
therefore leave a recoverable local point which has not yet reached S3. The public
recipient enables unattended encryption; no recovery private key is stored by the
updater. Existing snapshot size, disk reserve and capture time limits still apply.
Source-history or snapshot failure before target startup preserves/resumes the
source. Preparation checks and source restoration refuse operator-modified or
symlinked executables.

If the target may have opened databases, any failed/missing receipt, timeout or
helper crash leaves the target stopped in `manual_recovery`. The old binary is
**not** automatically started against potentially migrated data. Independent
systemd ExecStopPost uses the same lease and journal after SIGKILL/runtime timeout.
An unresolved operation pins its recovery archive against manual deletion and
retention; resolved points return to normal retention. No full automatic rollback
across an irreversible migration is promised.

When the Web UI is unavailable, use a verified current/source executable that
supports this recovery format:

```sh
yuhaiin update-status -path /actual/data
```

Inspect `phase`, `backupJobId`, `backupId`, `sourceSha256`, and `targetSha256`.
Keep the service stopped. Locate the required archive at
`/actual/data/.recovery-archives/<backupJobId>.yhb` and source executable at
`/actual/data/update/versions/<sourceSha256>.bin`; check the binary digest before
executing it. Preserve the failed state separately. Use that reviewed source's
existing CLI to verify/preview the archive with the external key, then explicitly
restore **original** mode using the preview's backup/source/target identities,
`-maintenance`, `-source-stopped`, `-restore-credentials` and, where appropriate,
`-adopt-startup`. See [the complete recovery procedure](recovery-archive.md).
Restoring older credentials can revive previously revoked devices/tokens: review
that decision before confirming. Copy the matching verified source binary to the
installed path with executable permissions, then start the service. Startup must
bind the restored transaction's backup and original-instance IDs to the update journal and pass actual
health checks before the result becomes `recovered`.

A lost launch acknowledgement preserves the admitted operation, staging and point.
Observe status rather than repeating the update POST. Only a still-`prepared`
operation may be explicitly cancelled through UpdateManage-protected `update.cancel`;
claiming the shared lease prevents cancelling active maintenance. Cancellation
cleanup is idempotent. Poll retries never resubmit Apply/Rollback. Page reloads bind
success to the client-generated operation UUID and reviewed SHA-256, not merely a
changed version string. An outage after five minutes shows offline inspection
instructions; it does not prove helper failure or stop a larger bounded snapshot.

Disabling `protectUpdates` requires a separate explicit no-point acknowledgement
for each install. It never permits a database-migrating target. Linux still uses
startup supervision when protection is disabled. macOS/Windows currently retain
their existing same-schema installed helpers under that opt-out; automatic
cross-database capture/supervision on those hosts is still pending. Management
TLS defaults and the full-backup archive format are unchanged.

## Verified target-schema preflight

Release builds now emit `<asset>.update.json` alongside each executable. The build
host inspects the target's embedded Go platform/CPU settings and streams its
SHA-256 without executing it. The descriptor is uploaded as a release artifact
and is itself included in `checksums.txt`. It binds the exact executable filename,
size, digest, OS/architecture, database startup guard protocol, protected-update receipt capability and ordered configuration /
management migration catalogs. Catalog entries include version, name, SQL-list
SHA-256 and whether the migration also runs a Go transform. This is a compatibility
declaration from the trusted release publisher, not an independent code audit,
release signature or proof that a Go transform is reversible.

The build-host tool explicitly uses baseline host CPU settings even for amd64v3 /
amd64v4 target artifacts. No target capability flag is executed: an old binary
might interpret an unknown flag as an ordinary server start. The tool can be run
manually after building the correctly named asset:

```sh
go run ./cmd/update-metadata -binary /artifacts/yuhaiin-linux-amd64 \
  -os linux -arch amd64
```

`Check for Updates` reports actual current and target schema versions. It reads
live WAL through read-only SQLite transactions, with no bootstrap, migration,
checkpoint or `immutable=1` shortcut. Configuration and identity catalogs must
match the target's supported prefix. If a management database exists, it is
checked even when its runtime authentication feature is disabled. An absent
management database is reported as absent; this does not enable authentication.
No new management user dependency or SQLite database owner is installed.

- `compatible`: both existing owners match and no database migration is needed.
- `migration_required`: the target adds migrations. A coordinated database
  recovery point and a supported installed host are required.
- `incompatible`: the target cannot recognize the observed catalog, including a
  downgrade, foreign migration name/statement descriptor or invalid live schema.
- `unknown`: metadata is missing/unverified or the installed host cannot inspect
  schemas. Existing releases without this descriptor remain visible for review
  but cannot be automatically installed.

Checksum, manifest and selected asset must agree. Checksums reject ambiguous
basename duplicates and normalize hexadecimal case. Manifest JSON rejects unknown
and duplicate fields and is limited to 512 KiB; checksum text is limited to 4 MiB,
and executable transfers to 512 MiB including excess-byte detection. Downloads
inherit a thirty-minute deadline and use the existing governed update HTTP client.
The UI submits the reviewed executable digest, and admission pins that digest through download. A rolling main/tag replacement after review or admission is rejected and requires another check; it never silently installs a different build. The manifest is re-fetched/checked at application time and the downloaded file
must match its size/digest. The privileged helper independently validates the
private staged sidecar, actual executable bytes and embedded platform/CPU settings,
then rechecks schemas after stopping the service before replacement. Windows also
uses the existing shared recovery-maintenance lease and restore-admission guard.

An older unlabelled binary is never assigned capabilities from its version string.
When archiving the *running helper's own executable*, `SaveHistory` can preserve
its actual compiled catalog in `<sha256>.bin.update.json`. Other arbitrary files
remain unlabelled. History responses inspect that descriptor against current live
databases; staging retains the descriptor and rechecks binary bytes. The Web UI
and backend both reject unknown, incompatible or migration-requiring binary-only
rollback. Old history files remain listable and manually recoverable after review.
The existing two-version retention also removes the corresponding descriptor.

No SQLite migration is needed for these additive API fields and private JSON
sidecars. The identity schema, archive format and configuration exports are
unchanged. The public release descriptor contains no deployment credentials or
private keys.

### Capability and compatibility limits

Schema compatibility does not prove application-level configuration compatibility
or migration reversibility. Protected updates additionally require the trusted
release descriptor to declare `updateGuard: 1` (Linux). A legacy descriptor without
that field may describe valid schemas but does not authorize protected installation
or binary rollback: its executable cannot produce the required startup receipt.
Old descriptors remain parseable and manually reviewable. Other platforms do not
claim this installed-host capability. Publisher checksums bind declarations to
bytes; they are not independent release signatures or a code audit.

The operation journal is one bounded 0600 atomic JSON record (maximum 2 MiB), not a
parallel configuration/database store. Existing backup settings/history persist
`protectUpdates` and `updatePoint` in their JSON payloads; no SQLite migration
beyond 23, identity-schema change or archive-format change is required. Status
exposes only public operation fields, not private paths, manifests or keys.

### Deterministic checks and resource scope

Tests cover same/forward/older/changed migration catalogs, missing owners, symlink
rejection, live-WAL changes after an earlier check, malformed/duplicate/oversized
manifests, manifest/binary checksum disagreement, platform/CPU mismatch, old
metadata absence, and actual executable tampering. The release-tool fixture builds
a program which writes a canary if executed, including an amd64v4 variant; metadata
generation leaves the canary absent. These tests use local files/HTTP stubs and
both SQLite drivers, with no public release service dependency.

`BenchmarkObservedSchemaCompatibility` includes opening and closing two live
read-only WAL database handles and transaction-consistent catalog reads. On the
local AMD Ryzen 5 5600G Linux/amd64 host, three samples measured 1.51–1.54 ms,
106.8–107.2 KB allocated and 816–817 allocations per check. This is a management
preflight operation, never forwarding or per-connection work; there was no
previous complete schema preflight to compare against. The result is not an
upgrade downtime, peak-RSS or WAN benchmark.
[Raw data](benchmarks/data/update-compatibility-2026-10-27/observed-schemas.txt).

Protected-update tests inject every durable recovery boundary, unknown executable
replacement, staging cancellation, no-point/migration consent, stale terminal
status and credential-aware paired restore. The isolated systemd runner builds
future-schema executables using Go overlays, without production fault hooks. It
checks a real schema-24 upgrade, failed readiness **after** committed migration,
SIGKILL at a fenced startup boundary, persisted points, offline CLI restore and
successful schema-23 source startup. Source startup is rejected before matching
restoration; fatal server initialization exits nonzero. Existing capture/HTTPS/S3
retrieval/restore crash scenarios remain in the same runner. Unit tests use local
servers/files; frontend synthetic browser fixtures are separate evidence.

`BenchmarkProtectedUpdateCoordinator` excludes fixture/database setup and measures
hash validation, durable journal/rename operations and the existing encrypted
snapshot collector with one minimal SQLite owner and two small real Go fixture
executables. Service readiness is synchronous in this benchmark. It is **not** an
end-to-end downtime, large-instance backup, cross-database throughput, peak-RSS or
WAN measurement. The actual service drill above supplies the startup/failure
correctness evidence; existing full-backup streaming measurements cover larger
inventories. No journal lookup or hashing is added to forwarding/dial paths.

On the local AMD Ryzen 5 5600G Linux/amd64 host, three 300 ms samples measured
36.37–45.22 ms, 1.67–1.68 MB allocated and 10,785–10,834 allocations per fixture
operation. There was no prior complete protected-update coordinator to compare
against. [Raw data](benchmarks/data/update-protection-2026-10-27/coordinator.txt).

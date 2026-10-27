# Software update history and rollback

The built-in updater for service installations on Linux, macOS, and Windows keeps **the two most recently replaced executable files**. Updates and restorations use the same service-stop, executable-swap, and service-restart helper.

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

Open **About → Software Update → Previous versions**. Select **Restore** for a history entry and confirm. The page follows the same service restart and version checks as an ordinary update.

Only the **executable** is restored. Existing configuration, SQLite databases, and any migrations are not reverted. A binary downgrade may not be compatible with newer data.

The reliability branch now checks each configuration/management database's
known contiguous migration history, names and metadata version before bootstrap
writes or journal-mode changes. A future, foreign or incomplete schema is
rejected with an incompatibility error instead of silently skipping unknown
versions or applying configuration migrations to an identity database. Known
older prefixes still follow the existing transactional migrations; an empty
database or interrupted empty base bootstrap can initialize normally.

This startup guard does not establish that an arbitrary archived old binary is
safe: older binaries can lack the guard. Updater compatibility negotiation,
automatic pre-update recovery points and post-update rollback coordination are
still pending. Use a matching binary and verified database recovery point when
a migration is incompatible; executable history alone does not reverse it.

The [offline disaster-recovery CLI](recovery-archive.md) now verifies, previews
and activates a complete encrypted snapshot using a durable rollback journal.
Use its explicit original-instance or clone decision and startup instructions
when restoring databases/keys is necessary. It requires stopped writers and a
reviewed matching binary/schema; the updater does not yet create or coordinate
these points automatically. File activation reports awaiting_startup until the
actual restored service passes its startup checks.

## When the service cannot start

The Web UI requires a running server. When an update prevents yuhaiin from starting, use the archived file directly from an administrator shell:

1. Locate the actual installed executable and configured data directory. Use the `.json` sidecar to identify a snapshot, and verify that its binary's SHA-256 matches its filename.
2. Stop the installed yuhaiin service via `systemctl stop yuhaiin` (Linux), the configured launchd service (macOS), or `Stop-Service Yuhaiin` (Windows, elevated PowerShell).
3. Preserve the currently installed executable separately, then copy the selected `<sha256>.bin` **over the installed executable**, keeping the installed path and executable permissions. For example, on Linux: `sudo install -m 0755 /path/to/data/update/versions/<sha256>.bin /path/to/yuhaiin`.
4. Start the service again with its platform service manager and check its logs and health.

On macOS, use the existing launchd plist to boot out and bootstrap the system service while replacing the executable; on Windows, close any processes still holding the executable before copying it. These instructions are for emergency manual recovery only and do not alter the service installation layout.

Do not delete history entries while a replacement or recovery is in progress.

## Verified target-schema preflight

Release builds now emit `<asset>.update.json` alongside each executable. The build
host inspects the target's embedded Go platform/CPU settings and streams its
SHA-256 without executing it. The descriptor is uploaded as a release artifact
and is itself included in `checksums.txt`. It binds the exact executable filename,
size, digest, OS/architecture, startup guard protocol and ordered configuration /
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
  recovery point is required; automatic admission currently refuses this case.
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

### What this preflight does and does not complete

This prevents unknown old binaries from automatically opening newer databases.
It does **not** yet implement automatic paired executable/database recovery points,
post-update application health supervision or crash-safe coordinated update rollback.
A same-schema update still has the existing executable-swap/restart behavior.
Migration-requiring targets deliberately remain unavailable for automatic update
until the next recovery-point integration is implemented. A compatible catalog
also cannot guarantee that all application-level configuration is meaningful to
the target build. Use the existing authenticated offline recovery process with a
matching executable/database set when automatic admission is refused. Never copy
an unverified old executable over a deployment merely because a version looks older.

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

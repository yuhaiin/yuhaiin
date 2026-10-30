# Backup transfers and disaster recovery

Enterprise reliability is implemented in [backend #622](https://github.com/yuhaiin/yuhaiin/pull/622)
and [frontend #535](https://github.com/yuhaiin/yuhaiin-react/pull/535).
Configuration export remains distinct from encrypted full deployment recovery.
Managed local/S3 jobs, history, verified downloads/retrieval, confirmed Web restore,
offline CLI and protected updates extend the existing owners. Automatic disruptive
service maintenance is qualified for root-owned Linux systemd and lingering
systemd user services; other host and
durability limitations are stated in the operator guides. See the
[requirement evidence](enterprise-reliability-audit.md),
[managed workflow](managed-recovery-backups.md) and [safe updates](update-rollback.md).

## Data ownership inventory

| Owner | Persistent state | Recovery implications |
| --- | --- | --- |
| Configuration storage | `state.db`, with active WAL/SHM | Node, routing, DNS, inbound, Gateway and settings configuration; persisted node evidence and statistics. Gateway CA signing material is also in this database. Take a SQLite snapshot rather than copying a live main file. |
| Optional management authentication | `management.db`, with active WAL/SHM | Accounts, verifier/credential state, upstream secrets and security events. Has its own schema and connection ownership. A separate snapshot is not a globally atomic snapshot with configuration. |
| Management TLS | `management-tls.pem` | Self-signed listener certificate and key, managed by `pkg/management/tls`. Explicit externally configured certificate/key paths require a manifest mapping and an explicit restore decision. |
| Tailnet nodes | `tailscale/v2-<opaque-identity>/tailscaled.state`, compatible `lite.json` and configured legacy files | Machine/node identity is tied to node configuration. Only original-instance restoration should reuse it automatically; cloning requires new enrollment. Do not collect unrelated caches/logs from the directory. |
| ZeroTier nodes | `zerotier/<configured-identity>/`, owned by the ZeroTier identity store | Persisted machine identity must be included by its owner, with explicit original/clone semantics. Do not recursively copy unrelated deployment data. |
| External node/protocol references | Configured certificate, key and identity files | Resolve actual references, record dependencies and reject missing required files. Configuration-only export cannot promise recovery of these files. |
| Software updater | `update/versions/<hash>.bin` and metadata sidecars | Existing executable history is not a database restore point. A previous executable must not silently open an incompatible migrated database. |

[Offline full creation](recovery-archive.md) now collects the multiple-database/
file set under a confirmed maintenance window, including protocol identity
owners. It must not be described as an atomic online cross-database snapshot
merely because individual SQLite snapshots pass.

The management database catalog includes main's version 6 SSTP verifier and
version 7 Passkey migrations. Original-instance recovery preserves Passkeys;
a clone resets management identities and requires Passkey enrollment again.
Original-instance recovery retains active and revoked verifier state from the
snapshot; a clone creates a separate management identity database and does not
reuse those credentials. A version 5 database upgrades without fabricating an
SSTP verifier for credentials issued before that migration; such credentials
still require rotation for SSTP as documented by the existing credential owner.

## Existing S3 backup transfer

The existing configuration format, S3 credentials/settings and object name
`<instanceName>-state.db` remain in use. This legacy object is a sanitized SQLite
state snapshot, distinct from the JSON configuration export and from the full encrypted disaster-recovery archive. It still contains configuration-bound
sensitive material; transfer streaming does not provide archive encryption.

New configuration snapshots retain only the existing configuration-export
tables and schema metadata. They exclude managed certificate/ACME keys, DNS
provider tokens, the Gateway CA, runtime data and S3 access/secret keys. The
snapshot's S3 and automatic recovery/cleanup settings are disabled. Offline
legacy S3 restore imports configuration into the target's private copy and
retains that target's existing backup settings and credentials. A standalone
JSON configuration export also omits S3 credentials and disables backup and
maintenance consent; configure them again after importing it. Recognized inline
node/inbound credentials are removed, and affected nodes and listeners are
disabled; affected legacy nodes are deselected. Administrators must re-enter
credentials and explicitly enable the affected entries after import. Both
ShadowsocksR protocol and obfuscation parameters are removed because they can
contain a user key or custom HTTP headers. HTTP Mock payloads are also removed
because they can contain arbitrary sensitive bytes. Reconfigure affected entries
after import. Opaque URL
paths, custom data and unknown fields may still contain secrets, so both formats
require protection.
Stored route-list and GeoIP refresh errors are omitted because failures can
include full credential-bearing URLs. Route sources and refresh settings are
retained; only the backup copy is changed. The existing S3 snapshot also resets
the legacy list's last-refresh timestamp, while JSON export retains it.
Current-format Node and Inbound documents reject unrecognized fields before
either export or S3 upload, except recognized legacy credential aliases whose
values have already been cleared. Upgrade to a compatible server or remove the
unsupported fields before retrying; the backup is not uploaded on rejection.
Legacy endpoint formats still require special care because their historical
schema cannot establish the same unknown-field guarantee.
Subscription URLs are omitted because tokens may occur anywhere in their paths.
Publish passwords, paths and node lists are cleared so an imported publish
cannot expose nodes with an empty password. Recreate subscription links and
reconfigure publish targets and credentials after importing either format.
Gateway request/response header values, rewritten queries, header/query
condition values, and userinfo, query strings and fragments in Gateway backend,
health, filter and redirect URLs are also removed. Affected policies, filters and their Gateways are
disabled until an administrator restores the values and reviews the policy;
routes selecting such a Gateway reject connections while it is disabled, instead
of falling through to ordinary forwarding. An explicit re-enable clears this
import protection; unrelated, manually disabled Gateways retain their existing
behavior. Import these snapshots only into a version that understands the
`rejectWhenDisabled` Gateway property: older versions cannot enforce this guard.
JSON exports containing this guard use configuration format version 2, which
older JSON importers reject; other exports retain version 1. New importers
continue to accept version 1. The legacy S3 SQLite format has no equivalent
version gate, so do not restore it with an older server.
Other Gateways retain their enabled state. Import replaces existing subscription
links with the exported set, which is empty for new exports.
Previously uploaded snapshots are not rewritten or deleted by this change and
may contain the excluded secrets; review their storage and rotate exposed keys.

`VACUUM INTO` reads a consistent SQLite snapshot including committed WAL data.
It writes into a private temporary directory; the sanitizer uses the shared
configuration allowlist, rebuilds the derived search index and compacts deleted
pages. Unknown virtual tables are refused rather than exported without a known
sanitizer. The file is opened as a seekable stream and removed on every
success/error/cancellation path. Uploads no longer allocate a byte slice the size
of the database. The source is not a raw copy of the live WAL database.

`go test ./pkg/app/backup -run '^$' -bench '^BenchmarkConfigurationSnapshot$'
-benchmem -benchtime=1s -count=2` compares 1,000 legacy and 1,000 current node
rows plus 10,000 Gateway statistics rows on a warm local filesystem. On a Ryzen
5 5600G, two runs before endpoint redaction took 24.2–24.4 ms and about
52–53 KB/1,400 Go allocations per snapshot; after, they took 32.3 ms and
about 1.92 MB/52,300 allocations. Allocated bytes are cumulative, not peak RSS.
With current-format Node and Inbound field validation, the same fixture measured
32.46–33.00 ms and about 1.92 MB/52,300 allocations before the validation,
versus 33.77–34.18 ms and about 2.61 MB/58,200 allocations after it (three runs,
`-benchtime=2s`, same host, local warm filesystem). This measures backup
creation rather than transfer or forwarding; allocation counts are cumulative.
Raw [before](benchmarks/data/configuration-backup-2026-10-30/before-typed-validation.txt)
and [after](benchmarks/data/configuration-backup-2026-10-30/after-typed-validation.txt)
results are retained.
The same fixture plus 1,000 route lists containing refresh errors measured
36.80–36.91 ms and about 2.61 MB/58,200 allocations before removing those
errors, versus 59.77–59.97 ms and about 4.71 MB/99,600 allocations after (three
runs, `BenchmarkConfigurationSnapshotWithRouteRefreshErrors`, `-benchtime=2s`,
same host and warm filesystem). This exercises worst-case error-bearing list
documents; allocations are cumulative, not peak RSS. Raw
[before](benchmarks/data/route-backup-2026-10-30/before-redaction.txt) and
[after](benchmarks/data/route-backup-2026-10-30/after-redaction.txt) results are
retained.
The sanitizer processes at most 128 rows and roughly 1 MiB of replacements per
batch, plus one potentially larger configuration document. The fixture excludes
S3 transfer and does not establish performance for a large production database.

`pkg/s3` keeps its API and uses the AWS SDK v2 client instead of `simples3.FilePut`:
the latter allocates the complete object both before signing and during signing.
The SDK versions already present in the repository module graph are pinned;
there is no default/environment credential discovery. HTTPS verification stays
on, requests use the existing proxy, and HTTP redirects are rejected. Explicit
HTTP endpoints remain supported for existing local S3-compatible deployments.
Custom endpoint addressing preserves its previous path-style behavior.

Object requests have at most three attempts and at most two seconds retry
backoff. Uploads above 16 MiB use sequential 16 MiB multipart sections with one
in flight; no part-sized heap buffer is needed for the seekable source. Failed
or cancelled multipart uploads attempt abort with a separate five-second
cleanup deadline. A provider outage can prevent abort; remote orphan cleanup
still needs a provider lifecycle policy. Objects are capped at 100 GiB.

The application bounds a backup operation to ten minutes and cancels active
manual/periodic transfers when the Backup component closes. Its schedule has one
owner goroutine and at most one timer. Reconfiguration cancels the old periodic
operation; disabled schedules do not poll the database. Concurrent manual
backup/restore requests receive a busy error. An interval longer than one year
is rejected rather than overflowing `time.Duration`.

After upload, the application streams the object back, checks its exact length
and BLAKE2b content/settings digest, then records `LastBackupHash`. A failed or
corrupt download never marks an upload verified. ETags are not treated as content
checksums. Saving this hash uses a compare-and-swap so an older upload cannot
overwrite new backup settings. Stable existing configuration can still skip an
unchanged upload; this is not a continuous guarantee against external deletion
of the remote object.

The compatibility `S3.Get` byte-slice operation has a 64 MiB download limit.
Large archive workflows must use `Download` into a private staging file instead.
Legacy restore now rejects active database owners before S3 download. Its offline
compatibility path validates the object, exports its configuration, imports that
into a private snapshot of the target store, and activates through the durable
restore journal. Local instance/authentication/CA/history state is retained;
source database identity is not adopted. It requires recorded startup facts and
a stopped-writer lifecycle owner. The existing online Web restore cannot perform
this maintenance transition yet and receives a clear rejection.

## Reproducible transfer measurements

Run the same checked-in `pkg/s3/upload_benchmark_test.go` against parent
`9c9acaf8` and the current implementation:

```sh
go test ./pkg/s3 -run '^$' -bench '^BenchmarkS3Upload$' -benchmem -benchtime=300ms -count=3
```

Linux/amd64, Go 1.27.2, Ryzen 5 5600G. Median allocation totals per operation:

| Object | Parent | Streaming implementation |
| --- | ---: | ---: |
| 1 MiB | 3,368,869 B | 110,009 B |
| 8 MiB | 25,556,785 B | 108,639 B |
| 32 MiB | 110,905,422 B | 316,730 B |

These are allocations from signing/hashing plus loopback HTTP transfer. The
preallocated input fixture is outside the measured loop. The 32 MiB upload now
uses multipart, so it has additional requests/allocations while avoiding whole
object buffers. This measures cumulative allocation, not peak RSS, SQLite
snapshot cost, archive encryption, disk capacity or public-network throughput.
A separate stripped Linux/amd64 default-tag build (`go build -trimpath
-ldflags='-s -w' ./cmd/yuhaiin`) grew from 59,177,312 to 65,017,024 bytes
(about 5.57 MiB) with the mature streaming S3 client. This is a measured binary
size cost, separate from the transfer allocation reduction. Platform/release-tag
sizes can differ. The [AWS SDK upload documentation](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/sdk-utilities-s3.html)
describes seekable-source behavior; this component uses sequential SDK object
operations rather than a concurrently buffering upload manager.

Raw [parent](benchmarks/data/backup-2026-10-26/parent.txt) and
[current](benchmarks/data/backup-2026-10-26/current.txt) results are retained.

Tests use local HTTP/TLS servers and SQLite databases: exact upload/download,
finite retries, cancelled headers/transfers, chunked oversize and truncated
responses, untrusted TLS, multipart abort/complete failures, corrupt readback,
unchanged-upload suppression, concurrent settings changes, private staging,
repeated schedule changes and closure without goroutine leaks. Both supported
SQLite drivers must be tested with their required build tags (`fts5` for mattn).

The [encrypted archive and offline recovery commands](recovery-archive.md)
collect, validate, preview and activate deployment snapshots with crash rollback
and actual startup checks. Managed full-archive Web/S3 scheduling, retention and
paired update recovery points are implemented. Successful file activation alone
is not a successful service recovery.

The [managed full-backup workflow](managed-recovery-backups.md) extends this same
Backup/BackupStore/S3 owner with migration 21, bounded history, one scheduled
maintenance capture, post-restart verified upload and leased archive downloads.
Its Linux systemd system/user scope and remaining host limitations
are explicit; it does not make legacy executable rollback database-safe.

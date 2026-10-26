# Backup transfers and disaster recovery

Enterprise reliability is implemented in [backend #622](https://github.com/yuhaiin/yuhaiin/pull/622)
and [frontend #535](https://github.com/yuhaiin/yuhaiin-react/pull/535).
Full disaster recovery is still in progress. The transfer improvements described
here do not turn the legacy S3 state database object into a complete deployment
backup. Encrypted offline snapshot creation and verification are implemented;
coordinated restore, retention, recovery UI and software-update recovery points
remain required.

## Data ownership inventory

| Owner | Persistent state | Recovery implications |
| --- | --- | --- |
| Configuration storage | `state.db`, with active WAL/SHM | Node, routing, DNS, inbound, Gateway and settings configuration; persisted node evidence and statistics. Gateway CA signing material is also in this database. Take a SQLite snapshot rather than copying a live main file. |
| Optional management authentication | `management.db`, with active WAL/SHM | Accounts, verifier/credential state, upstream secrets and security events. Has its own schema and connection ownership. A separate snapshot is not a globally atomic snapshot with configuration. |
| Management TLS | `management-tls.pem` | Self-signed listener certificate and key, managed by `pkg/management/tls`. Explicit externally configured certificate/key paths require a manifest mapping and an explicit restore decision. |
| Tailnet nodes | `tailscale/v2-<opaque-identity>/lite.json`; migrated legacy `tailscaled.state` | Machine/node identity is tied to node configuration. Only original-instance restoration should reuse it automatically; cloning requires new enrollment. Do not collect unrelated caches/logs from the directory. |
| ZeroTier nodes | `zerotier/<configured-identity>/`, owned by the ZeroTier identity store | Persisted machine identity must be included by its owner, with explicit original/clone semantics. Do not recursively copy unrelated deployment data. |
| External node/protocol references | Configured certificate, key and identity files | Resolve actual references, record dependencies and reject missing required files. Configuration-only export cannot promise recovery of these files. |
| Software updater | `update/versions/<hash>.bin` and metadata sidecars | Existing executable history is not a database restore point. A previous executable must not silently open an incompatible migrated database. |

[Offline full creation](recovery-archive.md) now collects the multiple-database/
file set under a confirmed maintenance window, including protocol identity
owners. It must not be described as an atomic online cross-database snapshot
merely because individual SQLite snapshots pass.

## Existing S3 backup transfer

The existing configuration format, S3 credentials/settings and object name
`<instanceName>-state.db` remain in use. This legacy object is a sanitized SQLite
state snapshot, distinct from the JSON configuration export and from the future
full encrypted disaster-recovery archive. It still contains configuration-bound
sensitive material; transfer streaming does not provide archive encryption.

`VACUUM INTO` reads a consistent SQLite snapshot including committed WAL data.
It writes into a private temporary directory and the existing sanitizer removes
runtime history. The file is opened as a seekable stream and removed on every
success/error/cancellation path. Uploads no longer allocate a byte slice the size
of the database. The source is not a raw copy of the live WAL database.

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
The legacy restore still requires replacement with controlled staged recovery;
it currently cannot claim safe recovery while live SQLite writers are active.

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

The [encrypted recovery archive and offline create/verify commands](recovery-archive.md)
collect and validate deployment snapshots. They do not yet replace the legacy
S3 restore path or implement controlled deployment activation.

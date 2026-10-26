# Encrypted recovery archives and offline disaster recovery

The recovery archive codec extends the existing `pkg/store/backup.go` owner and
backup contract. Offline creation now collects a deployment snapshot set from
the existing database and protocol owners. Controlled offline activation, startup validation and crash rollback extend that
same owner. Full local/S3 scheduling, backup history/retention, Web restoration
and safe-update integration remain in progress in the
[enterprise reliability work](enterprise-reliability.md).
Do not treat successful archive verification as a successful restore/startup drill.

## Working CLI operations

Generate an external backup identity in a protected location separate from the
backup destination and deployment inventory:

```sh
yuhaiin recovery keygen -identity-file /private/offline/recovery.key
```

The command refuses to overwrite an existing identity file. It writes the
private X25519 identity with owner-only permissions and returns only its public
`age1...` recipient as JSON. A scheduled encryptor needs that public recipient;
it does not need the private identity beside its archives.

Stop the service and all external certificate/identity writers, then create an
encrypted snapshot set using the public recipient returned by keygen:

```sh
yuhaiin recovery create -path /var/lib/yuhaiin \
  -archive /backups/instance.yhb -maintenance -recipient age1...
```

`-maintenance` acknowledges that all writers are stopped, including older
binaries/embedded callers that do not participate in the lifecycle lock. The
command also refuses a live cooperating server or an embedded database owner.
It snapshots `state.db` and existing `management.db` through SQLite `VACUUM INTO`
(including committed WAL data); it never copies a live main file. Sequential
database snapshots plus protocol files form a consistent set only under this
explicit maintenance condition, not a globally atomic online transaction.

The updated server records nonsecret startup inputs after successful startup:
management authentication/TLS mode, file references, working directory, listener
address and external web directory. For an older/unbootable deployment supply
the actual inputs explicitly, for example `-management-tls self_signed
-management-auth -working-directory /srv/yuhaiin`. For file TLS also provide
`-https-cert`/`-https-key`; for external web assets provide `-eweb`. These are a
complete override, not a partial merge with recorded inputs. Incorrect inputs
can omit a real dependency; operators must match the service configuration.

The inventory includes the management TLS bundle or explicit certificate pair,
Gateway CA inside state SQLite, configured node/inbound/Gateway TLS references,
configured Tailnet/ZeroTier identity files, Nebula PKI files and configured web
assets. It does not initialize VPN clients, enroll identities or copy the whole
data directory. Logs, caches, unrelated protocol identities and temporary native
state files are excluded. Missing required files, malformed resources and
hardware-bound Nebula keys without an external recovery procedure fail creation.
Uninitialized Tailnet/ZeroTier identities are explicitly listed as requirements.
ZeroTier inventory uses only portable filename/namespace parsing. Unsupported
native targets keep the existing bridge stub; offline backup does not pull the
native loader into Android/BSD builds. CI checks that dependency boundary.

External files are stored under a hashed `dependencies/` archive name. Their
original absolute path is encrypted manifest metadata (`sourcePath`), never
authority to extract/overwrite an external destination. Relative configuration
references resolve against the original working directory. Restore validates and rebinds these references to confined target paths and
requires an explicit original-instance versus clone identity decision.

Optional traffic/connection history is excluded by default; `-include-history`
retains it at additional storage cost. Cumulative counters, FakeIP mappings,
account/credential state, quota totals, node evidence and active measurement
budget reservations remain. Staged copies alone are pruned. A stable instance
UUID is recorded in source metadata if absent; creation otherwise leaves source
configuration and identity contents intact. Use `-passphrase-file` instead of
`-recipient` for password encryption. `-timeout` defaults to 30 minutes and is
bounded to 24 hours. Cancellation removes incomplete output and private staging.

Verify an archive using the private external identity:

```sh
yuhaiin recovery verify -archive /backups/instance.yhb \
  -identity-file /private/offline/recovery.key
```

Or use a private passphrase file, rather than putting a secret in process
arguments or logs:

```sh
yuhaiin recovery verify -archive /backups/instance.yhb \
  -passphrase-file /private/offline/recovery-passphrase
```

Verification decrypts into a randomly named private staging directory, checks
the manifest, file lengths, SHA-256 digests, the final authentication chunk and
SQLite integrity/schema, prints the authenticated inventory, and removes the
staging directory. It does not start the application, change instance files,
open a management listener or provide private key contents. `-staging-parent`
can select an appropriate filesystem with enough space. SIGINT/SIGTERM cancels
streaming work. Key/passphrase files are bounded and require Unix 0600-equivalent
permissions; Windows uses the account's filesystem ACLs.

The verifier does not prove that every external dependency of an instance has
been inventoried, that a service can successfully start, or that an archive was
made by the original deployment. Those checks belong to the complete snapshot
and restore workflow. With public-key age encryption, anyone knowing a public
recipient can encrypt to it; AEAD integrity is not a sender signature. Restore
must still require a trusted source, instance/clone decisions and explicit
approval of identity/credential replacement.

## Preview and controlled offline restore

Use a trusted complete v2 archive, stop the service and all external writers,
and create the target data directory if it does not exist. Preview never writes
the target deployment; it decrypts/rebinds a disposable private staging copy:

```sh
yuhaiin recovery preview -path /var/lib/yuhaiin \
  -archive /backups/instance.yhb -identity-file /private/offline/recovery.key \
  -mode original
```

Review `manifest.id`, `manifest.instanceId`, `targetInstanceId`, `files`,
`runtime` and `warnings`. `targetInstanceId` is the existing UUID, `empty` for
an absent database, or `unreadable` for a damaged/unrecognized target. File
changes explicitly identify replacements, installations and removals. Identity
replacement requires all three confirmations again during activation:

```sh
yuhaiin recovery restore -path /var/lib/yuhaiin \
  -archive /backups/instance.yhb -identity-file /private/offline/recovery.key \
  -mode original -maintenance -source-stopped -restore-credentials \
  -confirm-backup BACKUP_UUID -confirm-source-instance SOURCE_UUID \
  -confirm-target-instance TARGET_UUID_OR_SENTINEL
```

Use values from your own preview. Original mode preserves the deployment UUID,
management credentials/verifiers and protocol machine identities. The source
must remain stopped to avoid duplicate identities. Restoring older security
state can revive revoked credentials/devices and rewind quota/usage totals;
`-restore-credentials` explicitly acknowledges this. A different application
version additionally requires `-allow-version-change` after compatibility
review. Platform/architecture differences and unknown schemas are refused.

Clone mode uses `-mode clone` in both commands and the same three identity
confirmations, without the original-only acknowledgements. It generates a new
instance UUID, creates a fresh management identity database, drops the old
management self-signed bundle and Gateway MITM CA, removes Tailnet/ZeroTier
machine files, rotates WireGuard/Amnezia private keys, and disables all restored
nodes, inbounds and Gateway listeners. S3 credentials/hash/schedule and optional
probe/speed schedules are cleared/disabled; the backup instance name changes to
avoid overwriting source objects. Other outbound authentication/certificate
configuration remains in disabled resources and requires administrator review
and re-enrollment before use. Clone mode does not issue replacement Nebula or
other externally signed identities. Bootstrap a new administrator only after
the controlled startup succeeds.

All installed paths stay inside the target directory. External assets retain
required web-relative layout under `dependencies/`; configured certificate,
key, Nebula PKI and native-library references are rebound to those files.
Tailnet legacy files are normalized to the current protocol-owned namespace.
A source path in the manifest never authorizes writing that original location.
Conflicting namespaces, missing references and unsafe paths abort before moving
any live files. The target must already exist; preview/restore currently require
the source platform and architecture. Activation requires working directory
fsync semantics and is currently unavailable on Windows. Creation/verification
and ordinary server startup keep their existing platform behavior.

### Activation, real startup and rollback

Restore first decrypts and validates the entire archive into private staging on
the target filesystem. After checking closed SQLite owners and the lifecycle
lock, it hashes/syncs originals and durably records a replacement journal before
moving files. Original inodes move into `.recovery-point-TRANSACTION_UUID/`;
staged files replace them through individually synced renames. The returned
state is **awaiting_startup**, not a successful service restoration.

Start the current CLI server with the returned `runtime` TLS/authentication,
certificate/key and external-web inputs. Match the existing service unit flags
and use the relocated paths returned by restore. Ordinary CLI startup checks
the journal before generating TLS material or opening databases. It marks one
startup attempt, opens the actual application/identity owners, verifies schema
migration and enabled inbound/Gateway readiness, then checks the newly started
local management listener using its exact certificate, SAN verification and no
proxy/redirects. This does not probe arbitrary VPN peers. Only then does the
transaction become **committed**. TLS/auth/file-input mismatch refuses startup
without silently weakening management security.

A startup error closes application/identity owners before restoring originals.
An interrupted activation, interrupted startup check, or interrupted rollback
is rolled back on the next CLI start; that invocation exits for operator review
and an ordinary restart. Existing TCP/UDP sessions are not migrated across a
restore: the maintenance window requires stopping their owners. A pending
transaction can also be explicitly aborted without starting the Web UI:

```sh
yuhaiin recovery rollback -path /var/lib/yuhaiin \
  -transaction-id TRANSACTION_UUID -maintenance
```

Rollback moves original inodes back rather than allocating another database-sized
copy; it consumes those original files in the failed operation's recovery point.
Recorded hashes distinguish files already restored during an interrupted rollback
from lost/corrupt recovery material. Corrupt/missing originals refuse automatic
rollback and leave the guard pending for manual recovery. A committed deployment
is never silently rewound by this command.

The active `.recovery-transaction.json` journal and each point's private
`.recovery-meta/transaction.json` contain bounded transaction metadata.
`.recovery-last-result.json` records the latest result when the filesystem allows
it; the active journal remains authoritative if history persistence fails.
Successful points retain original identity files under 0700 directories; these
points are private plaintext, require the deployment filesystem's protection,
and currently have no automatic retention cleanup. Never remove them during a
pending operation. The journal is capped at 4 MiB, replacement moves at 8,200,
and original files at 100 GiB in aggregate. Decrypted staging is private and
removed on ordinary completion/error; orphan staging after process death needs
operator review, not indiscriminate cleanup.

The managed CLI integrates the complete startup transaction. Embedded/Android
hosts currently fail closed at `app.Start` if a pending restore lacks its
controlled startup ID; host-specific coordination before preference/database
opening still needs integration. Web maintenance orchestration and backup/restore
API/UI are also pending. Do not present this CLI capability as their completion.

## Encryption and framing

Encryption uses [age v1](https://age-encryption.org/v1) through the mature
[Go age library](https://pkg.go.dev/filippo.io/age). Random keys, nonces, chunk
authentication and final-chunk handling stay in that library. Both the manifest
and file contents are encrypted/authenticated. No decryption key or passphrase
is recorded in the manifest, ordinary configuration or logs.

Two mutually exclusive key modes are supported:

- External X25519 public recipient / private identity. No password KDF is needed.
- Passphrase encryption using age's default scrypt work factor `logN=18`.
  Decryption rejects larger work factors before deriving a key. The fixed scrypt
  working memory is approximately 256 MiB, independent of backup size; KDF work
  is not interrupted halfway through. Cancellation is checked before/after it.
  The operation owner must serialize jobs; the primitive does not start workers.

The authenticated plaintext is a simple uncompressed length-framed archive:

1. Magic bytes `YUHAIIN-RECOVERY\0\1`.
2. Four-byte big-endian JSON manifest length.
3. Strict versioned JSON manifest (`format=yuhaiin-recovery`, `version=2`).
4. Each declared regular file's exact bytes in manifest order.
5. Authenticated EOF, with no additional plaintext or ciphertext accepted.

This avoids tar links, executable modes, ambiguous headers, decompression bombs
and archive-selected absolute destinations. It does not support compression or
symlink entries. The manifest records backup/instance UUIDs, creation time,
consistency mode, history inclusion, build/platform metadata, file roles, sizes,
SHA-256 digests and database schema versions.
Version 2 adds complete-inventory status, source directory, nonsecret startup
inputs, external-file source metadata and explicit unmet identity requirements.
Version 1 component archives remain verifiable but are never promoted to complete
deployment inventories. The authenticated framing magic is unchanged.

Hard limits are 1 MiB of JSON, 4,096 files, 100 GiB of aggregate file data,
1,024-byte portable relative paths, bounded encrypted overhead and 1,024-byte
key/passphrase input. Files are exclusive-created under an `os.Root` in a 0700
staging directory with 0600 permissions. Traversal, absolute/drive/ADS paths,
control characters, reserved devices, aliases/conflicting file paths, lifecycle
storage names and SQLite WAL/SHM/journal sidecars are rejected. Writers hash
immutable source files before encrypting and check them again while writing;
source changes abort publication. Atomic file publication never overwrites an
existing archive. Normal cancellation/failure removes temporary output/staging;
a process crash can leave private staging that the future job lifecycle must
identify and clean without touching an active operation.

## SQLite checks and maintenance boundary

Inspection opens the standalone snapshot read-only and immutable. It never
bootstraps or migrates the supplied file. Live sidecars are rejected; committed
WAL data must have been captured through a consistent SQLite snapshot operation.
`quick_check`, `foreign_key_check`, ordinary migration/metadata tables, known contiguous migration
names/versions, matching metadata and startup-critical tables are checked.
Unrecognized future/foreign/incomplete schemas are rejected. Recognized older
prefixes retain their original version during inspection. Staged restore opens
them with the current owner and applies its known transactional migrations.
An application-version difference requires explicit offline review and
`-allow-version-change`; unknown schemas remain rejected.
Ordinary database startup shares the migration-prefix check and rejects
incompatible stores before bootstrap writes/journal-mode changes. This is a
current-binary protection, not a guarantee for archived binaries predating it.

Both SQLite drivers apply connection-local limits: 64 MiB SQLite values,
1 MiB SQL and expression depth 64. Snapshot checks use a 2 MiB page cache and
trusted schema is disabled. These limits do not change live application
connections. A database requiring larger values is outside this verifier's
current supported bounds. Verification is a database integrity/schema check,
not a full application-startup or cross-resource reference check.

Server CLI startup and local `auth` maintenance now acquire the same persistent
`.configuration.lock` inode before opening identities, databases or generating
TLS material. Closing releases it without unlinking it. This protects future
offline activation against a cooperating current server. Existing older server
binaries, embedded application callers and other programs do not automatically
participate, so an operator-controlled maintenance window is still required.
Unsupported lock platforms retain normal server behavior, while full offline
snapshot/activation must reject unavailable coordination. Verification/key
creation do not replace any deployment files and do not require stopping it.

## Deterministic coverage

Local tests cover external-key and passphrase round trips, wrong keys/passwords,
header/middle/final-tag corruption, truncated chunks, authenticated missing/extra
content, digest errors, hostile KDF costs, invalid manifests/paths, conflicting
names, private permissions, source modification, cancellation, exclusive archive
publication and cleanup. SQLite tests capture committed WAL data with `VACUUM
INTO`, reject live/corrupt/future/foreign/incomplete stores and verify that
inspection does not migrate or change input. CLI tests exercise actual keygen,
creation, verification, secret-file handling and exclusion of server/auth startup
while an offline lifecycle owner holds the lock. Full creation tests check both
databases, authentication/CA/identity preservation, external dependencies,
history retention/pruning, missing/corrupt resources, size budgets and cleanup.
Protocol inventory tests do not load native tunnels or contact control servers.

Restore tests cover original/clone identity semantics, scoped and revoked
management tokens, external path rebinding, legacy Tailnet namespace migration,
credential/version/target acknowledgements, active owners, every file-move
failure, cancellation, interrupted activation/startup/rollback, corrupt saved
originals and newly created namespace cleanup. The CLI subprocess drill runs the
real server/database/TLS owners for original and clone startup. An occupied
inbound listener causes rollback and the previous deployment actually starts;
`os.Exit` after application startup skips all defers and the next invocation
rolls back before the old deployment starts. These use local listeners and
initialized verifier fixtures, not a password-login exchange or public network.
Reproduce with `go test ./cmd/yuhaiin -run '^TestRecoveryServiceStartupDrill$' -v`.


## Archive resource measurements

Run `go test ./pkg/store -run '^$' -bench '^BenchmarkRecoveryArchiveExternalRecipient$'
-benchmem -benchtime=300ms -count=3`. On Linux/amd64, Go 1.27.2, Ryzen 5 5600G,
median cumulative allocation for 1/16/64 MiB source files was respectively
286,705 / 286,875 / 287,096 B/op. The benchmark includes two source reads,
read-only SQLite inspection and external-recipient encryption to `io.Discard`;
fixture creation, disk output, password KDF and full inventory/maintenance are
excluded. This demonstrates bounded creation allocation for those inputs, not
peak RSS, decryption allocation, complete recovery cost or network performance.
[Raw results](benchmarks/data/recovery-2026-10-26/external-recipient.txt) are retained.

The complete offline-create path has a separate benchmark:
`go test ./pkg/app -run '^$' -bench '^BenchmarkFullRecoveryCreateExternalRecipient$'
-benchmem -benchtime=300ms -count=3`. With a minimal current configuration
database and one 1/16/64 MiB external-web asset, median cumulative allocations
were 362,006 / 359,875 / 372,676 B/op; median elapsed times were approximately
28 / 69 / 199 ms on the same machine. This includes SQLite snapshot/validation,
inventory, asset staging, hashing, encryption, file sync and disk publication.
Fixture creation and password KDF are excluded. It is a local warm-filesystem
measurement of this fixture, not peak RSS, a many-node deployment, authentication
database cost, slow-disk performance or a restore drill. There is no parent
equivalent for this new operation. [Raw full-create results](benchmarks/data/recovery-2026-10-26/full-create.txt)
are retained.

## Restore resource measurements

Run `go test ./pkg/app -run '^$' -bench '^BenchmarkFullRecoveryRestoreExternalRecipient$'
-benchmem -benchtime=300ms -count=3`. Linux/amd64, Go 1.27.3, Ryzen
5 5600G environment gives median 1/16/64 MiB asset activation times of about
8.77/32.67/108.56 ms and cumulative allocation of 1.973/17.718/68.051 MB/op.
This includes decryption, inspection, staged rewrites, file sync and activation
into an empty target. Fixture/encryption generation, cleanup, password KDF,
replacing large originals, rollback and server startup are excluded. There is
no equivalent parent operation. [Raw restore results](benchmarks/data/recovery-2026-10-26/full-restore.txt)
are retained.

Cumulative allocation grows with ciphertext because age v1.3.2 creates a fresh
plaintext buffer for each 64 KiB decryption chunk. These are consumed as a
stream; the implementation does not retain an archive-sized plaintext buffer.
A separate fresh-process test of the actual CLI with `GOMEMLIMIT=32MiB` reports
maximum resident set sizes of 79,476 / 88,768 / 90,892 KiB for 1/64/256 MiB
assets, respectively (about 78/87/89 MiB). That includes the linked server's
runtime/native overhead. GOMEMLIMIT is a soft Go memory target, not an RSS cap;
RSS is not a peak Go heap measurement. KDF and fixture generation remain outside
the measured process; activation is verified only to awaiting_startup. These
warm-local-filesystem fixtures do not establish slow-disk or multi-database
production capacity.

Reproduce the Linux RSS test without external Python dependencies:

```sh
go build -o /tmp/yuhaiin-recovery-fixture ./scripts/benchmarks/recovery
go build -o /tmp/yuhaiin-recovery ./cmd/yuhaiin
python3 scripts/benchmarks/recovery/memory.py \
  --binary /tmp/yuhaiin-recovery --fixture-binary /tmp/yuhaiin-recovery-fixture
```

The runner uses one fresh Python wrapper/one restore child per sample and Linux
`RUSAGE_CHILDREN.ru_maxrss`; fixture generation is a different process. The
external private key is generated in a separate protected directory and is
never printed. [Raw RSS results](benchmarks/data/recovery-2026-10-26/restore-rss.jsonl)
are retained. The real startup/crash drill above provides separate correctness
evidence, not a resource benchmark.

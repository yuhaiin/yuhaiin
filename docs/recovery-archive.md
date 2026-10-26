# Encrypted recovery archive and offline creation/verification

The recovery archive codec extends the existing `pkg/store/backup.go` owner and
backup contract. Offline creation now collects a deployment snapshot set from
the existing database and protocol owners. Controlled restore activation/crash
rollback, backup history, retention, safe-update integration and the Web UI
still require implementation in the [enterprise reliability work](enterprise-reliability.md).
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
references resolve against the original working directory. A later restore must
validate/rebind these references and decide original-instance versus clone
identity semantics before activation.

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
`quick_check`, ordinary migration/metadata tables, known contiguous migration
names/versions, matching metadata and startup-critical tables are checked.
Unrecognized future/foreign/incomplete schemas are rejected. Recognized older
prefixes retain their original version; a later restore layer must explicitly
handle the required upgrade and its rollback limits.
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

# Managed encrypted recovery backups

The existing **Configuration → Backup** page now distinguishes full encrypted
deployment archives from the legacy S3 configuration snapshot. It uses the
existing Backup owner, settings, SQLite migrations and S3 client. It does not
introduce another scheduling service or copy the entire data directory.

## Configure and run

1. Generate a backup identity with `yuhaiin recovery keygen -identity-file
   /private/recovery.key`. Keep that private file away from the server/archive
   destination. Paste only the returned public `age1...` recipient into the page.
2. Choose local storage or S3. S3 reuses the existing endpoint/bucket/credential
   settings; HTTPS certificate verification remains enabled. Explicit HTTP
   endpoints remain available for existing private S3-compatible installations.
3. Explicitly allow maintenance. Full capture stops the service and active
   connections. External certificate/identity writers must also be paused or
   coordinated by the operator during that window; stopping Yuhaiin does not
   stop unrelated programs. The coherent set is an offline maintenance snapshot,
   not a globally atomic online multi-database transaction.
4. Save the settings, then choose **Create full backup** and confirm the service
   interruption. Or explicitly enable the periodic schedule, accepting those
   interruptions. The browser does not need to remain online.

Automatic maintenance currently supports a root-owned Linux systemd installation
where the current process is the actual MainPID of `yuhaiin.service`. The helper
retains that account's UID/GID rather than acquiring a different file identity.
Standalone, unprivileged, macOS, Windows and embedded hosts need further host
integration; the offline CLI remains separate. Windows restore activation also
retains its documented directory-sync limitation. These are current support
boundaries, not completion of the full cross-platform recovery objective.

The full-backup interval is at least 60 minutes and at most one year. The default
is daily, with a 30-minute per-job deadline; the maximum deadline is 24 hours.
Schedules are disabled by default. Optional traffic/connection history increases
storage; required identity, quota, accounting and measurement-budget state is
always included. Existing manual Selector behavior and probe defaults do not
change. The legacy configuration snapshot interval is labeled in **minutes**,
matching the existing backend semantics.

## Maintenance and transfer lifecycle

Migration 21 adds `backup_recovery_history`, indexed by creation time and state,
with one queued/capturing request allowed at a time. Public-key policy and S3
destination fingerprints are frozen with the request. No private backup key or
duplicate S3 credential is stored in the history. Compare-and-swap transitions
prevent an old helper/upload/deletion from overwriting a newer state.

The installed-service host launches an independent transient systemd unit. It
stops the existing service, closes the real database/protocol owners, invokes
the existing offline inventory/SQLite snapshot/age writer, records the completed
ciphertext length/digest, and restarts the service. The systemd unit also has an
`ExecStopPost` restart action for abrupt helper death or its runtime deadline,
when Go cleanup cannot run. Updates and recovery helpers share a persistent
`.recovery-maintenance.lock` so they cannot concurrently stop/swap one deployment.

Encrypted files live at `<data-dir>/.recovery-archives/<job-uuid>.yhb`, beneath
private directories. Conflicting files are never overwritten or adopted after a
crash. Managed archive/maintenance paths are reserved against archive extraction.
The existing persistent `.configuration.lock` and closed-owner checks still
protect the actual snapshot window. The collector preserves its precise file
ownership and external-dependency inventory, documented in
[offline recovery](recovery-archive.md).

After restart, the existing Backup scheduler resumes pending uploads through its
normal runtime proxy, routing, DNS and traffic controls. No offline Direct
uploader is substituted. One owner goroutine and timer manage legacy and full
schedules; one transfer runs at a time. A full schedule's first due time is
anchored to startup, so frequent legacy ticks cannot postpone it indefinitely.
Invalid imported policies cannot create a millisecond retry loop.

S3 uses `recovery/<instance-uuid>/<backup-uuid>.yhb`. The upload remains unverified
until streaming download produces the exact expected ciphertext length and
SHA-256. This is explicitly separate from decrypting/authenticating the archive.
A destination change refuses the old upload; it cannot redirect that request to
a different bucket. Local corruption also prevents upload. Existing finite SDK
request/part retries apply. Interrupted transfers retain their local archive for
restart, with at most three whole-job attempts; a failed completed archive can be
explicitly retried after administrator review. Ordinary provider errors are
recorded as finite error codes rather than storing credential-bearing responses.
Managed encrypted objects are capped at 100 GiB including framing/encryption
rather than only plaintext file data.

The independent crash-restart fallback acquires the same maintenance lease as
capture and executable updates before starting the service. It cannot restart
SQLite while another helper owns a binary swap. Empty full-backup queues and
unconfigured retention do not acquire the manual configuration-backup lease.
Transient schedule/history or service-manager failures trigger a bounded
one-minute recheck, without launching an unrelated configuration backup.

## History, verification, download and retention

The page shows up to 1,000 recent records: queued, capturing, local-ready,
uploading, S3-readback-verified, failed and deleting. The registry has a hard
4,096-record bound. Actual ciphertext size, timestamps, target and verification
results remain distinct. Upload failure never becomes a reliable-backup result.
A restarted process marks interrupted captures failed; it does not adopt an
orphan or partial file. Interrupted uploads resume from unchanged ciphertext.

**Verify archive** uses a supplied external private backup identity for a single
request. The backend serializes this work, compares the recorded ciphertext,
decrypts into private staging and checks the authenticated manifest, identity,
file digests, final authentication tags and SQLite schemas. The key never enters
settings, history, logs or a key-read API. The last check's result/time is stored;
a wrong key is not presented as proof that the S3 object itself was corrupt.
Cancellation is distinct from authentication failure. Passphrase verification is
also supported by the API/codec; scheduled creation uses public recipients.

Downloads require `backup:manage`, have a four-download lease limit, and stream
from a managed UUID, not an arbitrary
filesystem path. Native file-saving browsers pipe large responses directly into
the chosen file. Other browsers have an explicit 64 MiB fallback, including
chunked responses without Content-Length; larger downloads require a streaming
browser or authenticated HTTP client. There is no archive-sized backend buffer.

Retention has count/age limits, defaulting to 10 successful points and 30 days.
Failed attempts do not consume successful slots. The newest successful point is
always retained, even if older than the age target; an administrator can delete
it explicitly after confirmation. Active uploads and download leases cannot be
deleted. Deletion records its intent before removing the exact owned S3 object
and local UUID file, then removes history; an interrupted deletion resumes
idempotently. Changed S3 destinations refuse remote cleanup and retain an error
for review. No bucket listing/prefix deletion is used.

This retention applies to managed encrypted backup archives. The plaintext
`.recovery-point-*` originals retained by offline restore transactions are a
different lifecycle and still require protected operator-managed retention.
No background cleanup indiscriminately removes private staging or active files.
Clone restoration clears source backup history and disables maintenance consent
and schedules so it cannot resume source uploads or overwrite their objects.

All operations retain the existing management authorization model, including
`backup:manage` on the raw download route. UI deletion/maintenance is confirmed;
archive verification supplies no certificate/private-key retrieval interface.

## Qualification

Hermetic tests cover actual SQLite owner exclusion, coherent encrypted capture,
stop failure, cancellation, existing-file protection, restart failure, upload
readback corruption/truncation, destination/local-file changes, interrupted
upload state, active-download deletion protection, ownership-bound S3 deletion,
count/age retention and preserving the newest point. Verification tests check
wrong identities, tampered ciphertext and absence of private input in history.
Frontend tests exercise disruptive/deletion confirmation, active-job controls,
transient key clearing and bounded/streaming browser downloads.

For the real service/fault drill:

```sh
python3 scripts/bench/recovery-maintenance/run.py
```

It builds/runs an isolated systemd container with the actual production binary.
The test requests a full S3 snapshot through actual authenticated HTTPS, requires
a changed service PID, verifies downloaded ciphertext and the decrypted inventory,
then kills a helper during a second capture. The source service must restart via
ExecStopPost, retain its management session and reject the incomplete archive.
A disk-backed local object server avoids external S3 dependencies. The fixture
never mounts the host service socket, host data or host PID namespace. See
[the runner](../scripts/bench/recovery-maintenance/README.md) for rootless and
disposable-runner options. This is fault/correctness qualification, not a WAN
or production-capacity benchmark.

Safe-update schema negotiation/recovery points, broader platform service coordination, restore-point
retention, periodic recovery drills and ACME remain required work. This feature
does not claim completion of the entire enterprise reliability objective.

## Control-plane resource measurements and metrics

`go test ./pkg/store/backup -run '^$' -bench '^BenchmarkRecoveryHistory$' -benchmem
-benchtime=300ms -count=3` measures the indexed history query plus DTO decoding.
On Linux/amd64, Go 1.27.3, Ryzen 5 5600G, median 100/1,000-record reads take
about 0.34/3.20 ms and cumulatively allocate 187 kB/2.03 MB. Database fixture
population is excluded; there is no equivalent parent history operation. These
are warm local SQLite control-plane measurements, not transfer memory, peak RSS,
forwarding latency or restore performance. [Raw data](benchmarks/data/recovery-2026-10-26/history.txt)
is retained. Existing streaming archive/transfer resource measurements remain
scoped to their recorded fixtures and revisions.

The existing metrics endpoint adds finite target/state gauges for the latest
1,000 retained full-backup records, the latest completed local or S3-verified
point's timestamp, and active download leases. They use atomic runtime snapshots,
never SQLite/file/provider queries on scrape, and have no UUID, URL, user or
bucket labels. These are recent retained-state gauges rather than cumulative
success counters or claims of a successful restore drill. A pedantic-registry
test collects after removing the store and checks bounded label domains and
stale-snapshot protection.


## Web archive import and authenticated preview

Migration 22 adds bounded, expiring import records to the existing BackupStore.
The Backup page accepts encrypted files through a streaming, BackupManage-gated
upload. There are at most two imports and 100 GiB of combined ciphertext per
deployment. One existing Backup operation lease serializes uploads, decryption
and transfers. A ten-minute operation timeout and cancellation close blocked
request bodies. Known lengths, chunked input, short writes and incomplete files
are checked without buffering an archive-sized byte slice.

Private files live inside `.recovery-imports/<server-issued-uuid>/`. The upload
records its actual size/SHA-256. Preview checks that same open file, then reuses
the existing age decoder, SQLite/platform/inventory verification and confined
original/clone projection. The validated plaintext size is checked against
available space before staging, with a 256 MiB reserve. Uploads recheck free
space periodically. These checks cannot reserve space against unrelated writers;
a filesystem error refuses the import without changing the active deployment.

A preview displays source/target/resulting instance IDs, application version,
file install/replace/remove decisions and identity/credential/quota warnings.
The decryption request is limited to 16 KiB. Its private identity/passphrase
never enters the import record, configuration draft or returned plan. The UI
clears its input on submission. Prepared plaintext remains in private server
staging for the import's 30-minute preview lifetime; admitted maintenance retains
its files until its controlled recovery resolves. This is sensitive deployment
material. Listing, preview and discard are also bound to the creating principal
when management identities are enabled. Existing embedded hosts retain their
existing authorization model.

Confirmed discard removes only the owned UUID container, including interrupted
decoder staging not yet published in metadata. The existing Backup scheduler
expires records with its one timer and resumes interrupted deletions. Interrupted
uploads are removed at startup. Staging survives a browser refresh until expiry;
after server failure, a missing or changed file is rejected rather than adopted.
Each request exclusively creates its UUID container. Failed unpublished uploads
remove that owned ciphertext before registry cleanup, so unavailable database
writes cannot retain their disk budget; startup reconciles interrupted records.
Aliased namespace directories are rejected without touching other files.
Directory synchronization uses the existing filesystem/platform requirements.
Imports are excluded from configuration exports and all full backup snapshots,
even when optional business history is included; the source database is not
changed. Clone rewriting also clears source import records.

Read-only retention plans skip the operation lease when no deletion is due.
Under the lease, the plan is loaded again before side effects. This prevents
an upload's reschedule event from spuriously rejecting the next preview as busy.
Tests reproduce this admission failure before the fix and exercise its real
HTTPS call sequence in the isolated installed-service drill.
Pending work also retains a bounded one-minute fallback recheck when another
operation holds the lease; completion reschedules after releasing the lease.

### Confirmed Web activation

Migration 23 adds a partial unique index permitting one `activating` import.
Admission and backup-capture requests check each other's pending states in SQLite
transactions. The existing scheduler pauses during a restore handoff; after an
uncertain helper failure, its bounded recheck resumes work without a browser.

On a root-owned Linux `yuhaiin.service`, **Review and restore** requires typing
the target instance ID and acknowledging service interruption/data replacement,
restored TLS/authentication/listener inputs, and the selected identity semantics.
Original recovery additionally requires stopped-source and revoked-credential/
quota-rewind consent. Clone recovery requires fresh administrator enrollment,
protocol re-enrollment and disabled outbounds/listeners/source schedules. Replacing
a different resulting identity has its own acknowledgement. All IDs and consent
are bound to an immutable preview ID; another preview invalidates old consent.
The Web flow accepts the same application version/platform only. Reviewed version
changes remain an explicit offline operation.

Preview seals the **projected** plaintext files, including rewritten SQLite and
clone identities, using streamed size/SHA-256 and observed schema versions. It
stores no decryption key. The independent service helper takes the existing
maintenance lease, stops the service, excludes active SQLite/lifecycle owners,
revalidates staged contents, target identity and protocol-file inventory, then
uses the existing activation journal/recovery point. A clean shutdown may remove
WAL/SHM sidecars; their current originals are saved if present and never installed
from an archive.

A service-manager `start` is not success. The helper waits for the actual
startup checks to commit the matching transaction. Failed start, timeout and
helper death recover original files/startup bindings before restarting the
original service. The transient unit's independent `ExecStopPost` also handles
SIGKILL. A committed transaction is preserved. Cleanup/history errors after a
safe file outcome do not prevent a service restart; unremoved private staging
keeps its ownership metadata and a visible cleanup failure for operator action.
Corrupt rollback originals still fail closed with the journal retained for CLI
recovery, rather than starting a partial deployment.

The API returns **admission**, not a committed restoration. A disconnect can occur
after that admission is persisted. The browser never automatically replays the
request; reconnect using the restored listener/certificate and refresh the latest
restore result. Authentication/session state may change, and clone recovery
requires new administrator setup. An unclaimed admission can be discarded only
while holding the helper's maintenance lease. Active maintenance is excluded
from ordinary expiry cleanup. Successful restore removes its private container;
failed activation normally retains ciphertext but requires a new authenticated
preview. Other host integrations continue to use the offline CLI.

The browser regression covers explicit confirmations, pending versus committed
state, and 1440/360/320 px layout using synthetic data. The real HTTPS/systemd
integration separately proves an actual restored configuration, changed service
PID, reopened authentication and a committed startup transaction. Unit faults use
real SQLite/files and virtual time for startup timeout, staging corruption,
foreign identity, missing consent, concurrent admission and cleanup failures.

`BenchmarkRecoveryImportStaging` measures the actual opaque upload/registry/
fsync/discard path with incompressible source data allocated before timing.
On Linux/amd64, Go 1.27.3, Ryzen 5 5600G, median 1/16/64 MiB operations take
1.43/16.83/66.30 ms and cumulatively allocate approximately 49.6/51.8/56.4 kB.
This is local file staging including SQLite and cleanup. It excludes HTTPS,
archive authentication and source-fixture allocation, and does not measure peak
RSS or WAN throughput. The parent has no equivalent import operation.
[Raw results](benchmarks/data/recovery-2026-10-27/import-staging.txt) are retained;
the benchmark is also run by the existing reliability workflow.

The current Web import publisher requires directory synchronization. Windows
publication remains explicitly unsupported while its private staging/durability
and service coordinator are completed; cross-compilation is not evidence of a
working Windows restoration workflow.


### Race-suite fixture budget

The Web restore fault matrix uses real configuration/management SQLite, TLS and
Gateway dependencies. General file/state/admission cases use the basic deployment
fixture; dedicated native cases retain real Tailnet/ZeroTier inventory. The latter
verify current-path projection, original versus clone identity handling, rollback
and same-size native-file tampering. All production credential KDF work remains
unchanged.

This separation avoids repeatedly deriving a 600,000-round Tailnet namespace in
unrelated cases. The preceding remote race jobs reached the 180-second package
limit while running that KDF, without a reported data race. The updated combined
suite passed locally with affinity limited to two CPUs and GOMAXPROCS=2: recovery
83.3 s, online backup 92.9 s. The package deadline and behavioral assertions were
retained. These are test-resource measurements, not forwarding or WAN benchmarks.

## Recover a missing or damaged local S3 copy

The history distinguishes **Local copy missing**, a present private regular file
with the recorded size, and unavailable/incorrect-size/incorrect-permission files.
Presence is a fresh filesystem observation, not proof of decryption or a retained
file lease. Merely opening or refreshing the page never downloads S3 objects.

For a previously verified S3 upload, choose **Retrieve / repair local copy** and
confirm the displayed download size and possible replacement. Retrieval:

- Reuses the recorded object key, size and SHA-256, the existing S3 client and
  governed outbound proxy. It never accepts a request-supplied endpoint or key.
- Refuses disabled or changed S3 configuration, including changed credentials;
  restore the original settings first. It validates the original UUID namespace.
- Uses the existing shared backup operation lease, excludes active archive
  readers and retention/deletion, and admits one transfer at a time. Service
  shutdown cancels it. The deadline is the shorter of the recorded policy timeout
  and ten minutes; the hard ciphertext size limit remains 100 GiB.
- Streams to an exclusive owner-only `ARCHIVE.yhb.download` file beside the final
  archive. It checks initial capacity for the full download and rechecks free
  space during writes, preserving the existing 256 MiB deployment reserve.
- Validates the exact byte count and SHA-256 before publication and directory
  synchronization. A missing destination is published exclusively; repair keeps
  the old copy until the replacement is completely verified. Symlinks are refused.
  Normal transfer, integrity or cancellation failures before publication preserve
  the old copy and remove temporary output. A filesystem failure after publication
  can leave a verified copy while reporting failure; refresh and explicitly verify.

The page supports cancellation and records running/verified/failed/cancelled/
interrupted retrieval separately from upload evidence and authenticated archive
checks. Lost HTTP responses and cancellation near publication require refreshing
history; the UI never claims an uncertain request rolled back or retries it
silently. Restart removes only temporary output for a recorded running retrieval,
marks it interrupted, and does not automatically redownload. An inaccessible or
aliased temporary file requires operator filesystem repair. A valid existing
local copy is checked and reused without another download.

**Ciphertext retrieval is not deployment restoration or decryption verification.**
Use **Verify archive** with the external private backup identity, then the existing
upload/authenticated preview/confirmed restore workflow. The transfer result does
not overwrite earlier archive-authentication failures. A previous `verified`
upload state describes its original readback, not a guarantee that S3 objects can
never subsequently be removed or changed.

### Fetch when the deployment and its history are unavailable

Use **Save recovery metadata** while the history is available. Retain that small
JSON record outside the deployment, alongside a separately protected S3 settings
file and the external backup identity. The metadata contains public backup and
instance IDs, object key, ciphertext length/digest and operation status. It never
contains S3 credentials or a private decryption identity. Protect its integrity:
a SHA-256 supplied by the same untrusted server as the object is not independent
verification.

For example, create `/private/s3.json` with owner-only permissions and the existing
S3 contract (supply actual values privately; do not paste secrets into commands):

```json
{
  "enabled": true,
  "endpointUrl": "https://s3.example.invalid",
  "region": "us-east-1",
  "bucket": "deployment-backups",
  "accessKey": "SET_PRIVATELY",
  "secretKey": "SET_PRIVATELY",
  "usePathStyle": true
}
```

```sh
yuhaiin recovery fetch -archive /backups/retrieved.yhb \
  -s3-config-file /private/s3.json -metadata-file /private/saved-point.json \
  -timeout 30m
yuhaiin recovery verify -archive /backups/retrieved.yhb \
  -identity-file /private/recovery.key
```

`fetch` shares the streamed downloader and size/digest/publication checks. It opens
no deployment database or listener, does not need a running service, and uses the
system network explicitly configured by this offline operation. Unlike runtime
retrieval, no live Routing/Traffic Control owner is available. HTTPS certificates
are verified. The output path must not already exist; the CLI never replaces it.
An interrupted CLI `.download` file must be inspected and removed manually before
retrying. No keys appear in JSON/parser/provider diagnostics. Continue with the
existing offline preview/restore and original-versus-clone identity confirmations;
fetch itself never activates files. If independent history metadata was lost,
use the S3 provider's download tools and authenticate the archive with the existing
`recovery verify`; do not manufacture a trusted digest from the object itself.

The optional retrieval fields are additive JSON in migration 21's existing
`backup_recovery_history.data_json`; no table, schema-version increment or new
SQLite owner is needed. Runtime presence is not persisted.

### Verification and local resource measurements

Deterministic local HTTP/TLS tests cover missing copies, explicit repair consent,
same-size corruption, truncation, fixed/chunked oversized objects, cancellation,
changed destinations/credentials, wrong object ownership, byte/space budgets,
reader/deletion/concurrent-transfer exclusion, restart cleanup and rejected TLS.
A real encrypted deployment archive is retrieved, decrypted and inventory-checked.
The installed-systemd drill removes its actual local archive, verifies permission
rejection, retrieves through the live API without changing the PID, then completes
authentication and actual original/clone service restoration.

Run the loopback resource benchmark with:

```sh
go test ./pkg/app/backup -run '^$' -bench '^BenchmarkRecoveryArchiveRetrieval$' \
  -benchmem -benchtime=300ms -count=2
```

On this AMD Ryzen 5 5600G Linux/amd64 host, 1 MiB took 1.71–1.75 ms and
16 MiB took 23.2–23.5 ms. Measured allocations were 95.6–99.6 KB/operation
and 704–728 allocations/operation. Both sizes include client creation, S3 signing,
disk writes, hashing and synchronized publication. The immutable HTTP fixture is
allocated before measurement; B/op is not peak RSS. There is no equivalent parent
operation for a before/after comparison, and these are local filesystem/loopback
results, not a WAN speed claim. [Raw results](benchmarks/data/s3-retrieval-2026-10-27/retrieval.txt).

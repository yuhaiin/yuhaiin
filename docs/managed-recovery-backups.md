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

Web restore upload/preview/activation and recent-restore UI, safe-update schema
negotiation/recovery points, broader platform service coordination, restore-point
retention, periodic recovery drills and ACME remain required work. This feature
does not claim completion of the entire enterprise reliability objective.

## Control-plane resource measurements and metrics

`go test ./pkg/store -run '^$' -bench '^BenchmarkRecoveryHistory$' -benchmem
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

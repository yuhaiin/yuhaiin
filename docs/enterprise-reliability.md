# Enterprise reliability delivery

This work is based on backend main `dada430a` (including #628) and frontend main `391e4db`.
It does not depend on the open enterprise identity/resource/security stacks
(backend #618/#620/#621, frontend #530/#532/#533).

The authorized scope contains three complete stages, each with backend/frontend,
persistence, tests, resource measurements and documentation. Review and delivery
now use one PR per repository throughout all three stages.
A component delivery below does not complete the overall scope.

## Stage 1 — intelligent outbound selection (in progress)

Only active delivery/review entries: [backend #622](https://github.com/yuhaiin/yuhaiin/pull/622),
[frontend #535](https://github.com/yuhaiin/yuhaiin-react/pull/535). Both remain draft
until the complete three-stage scope is implemented and verified. Previous
component PRs are closed as superseded; their commits are retained here.
Further work continues in these two PRs, both targeting main.

Implemented in those PRs:

- Opt-in selector policy and schema 18; old manual configurations/exports retained.
- Independent TCP/UDP evidence extending existing node observability; bounded observed-traffic means, recent TCP dial summaries and distinct active-test metrics in Node details.
- Six strategy calculations, fresh comparable RTT and active-capacity semantics.
- Hysteresis, hold/cooldown, sticky failover, manual lock and explicit fallback.
- Precomputed immutable snapshots and weighted new-connection admission.
- Candidate deletion protection and node/Set/endpoint dependency-cycle checks.
- Verified, streaming, bounded download/upload tests with shared durable daily budget, explicit upload protocol/consent, independent freshness/smoothing and a separate HTTPS endpoint tool.
- Real policy editor, evidence/score/event views and manual test controls in EN/JA/KO.
- Deterministic/local tests, 1,000-reader concurrency coverage and microbenchmarks.

The monitoring follow-up adds cancellation propagation, shared bounded and
deduplicated schedules, global settings/selector overrides (migration 19),
network-interface/native lifecycle rescheduling, explicit TCP/HTTPS/DNS/STUN
evidence and optional periodic budgeted downloads, with real frontend controls.
The circuit follow-up adds Closed/Open/Half-open admission, finite recovery
quotas, independent TCP/UDP evidence, configuration generations, credential
snapshots, and real frontend controls. Remaining qualifications are not done.

Still required before Stage 1 is complete:

- Full qualification of shared scheduling under cancellation, network changes
  and larger deployments; native-provider adapters for protocols where available.
- Protocol framing/construction cost qualification beyond logical Node-stream
  budgets; routing/admission/live shaping use existing app components.
- Final qualification of worst-case churn/snapshot/resource measurements and
  broader real-transport connection benchmarks. Deterministic TCP/UDP creation,
  loopback TCP and 1,024 concurrent admission tests are now present.
- Browser desktop/mobile verification and required remote CI verification.

## Stage 2 — disaster recovery and safe updates (in progress)

Reuse existing app/store Backup and S3 code. Inventory data ownership first:
configuration state SQLite, management auth SQLite when enabled, management TLS
bundle, gateway CA in state DB, and protocol-owned identities. Avoid copying the
whole data directory. Use coherent SQLite snapshots and an explicit coordinated
maintenance/offline mode for cross-database consistency. Build a versioned,
streaming authenticated-encrypted archive with staged verification/restoration,
rollback recovery points, retention, S3 download verification and offline CLI.
Integrate update/schema compatibility and real restore/startup fault injection.

The first Stage 2 change fixes shared transfer/scheduling prerequisites in the
existing Backup/S3 components: streamed private SQLite snapshots, bounded S3
multipart uploads, context cancellation, finite retries, download verification,
a single cancellable schedule owner, and settings compare-and-swap after upload.
See [backup transfer and recovery ownership](backup-recovery.md).

The encrypted archive codec and offline `recovery keygen`/`recovery create`/`recovery verify`
commands are implemented with age, authenticated manifests, private staging,
strict path/size limits and read-only SQLite schema/integrity checks. The server
and local auth maintenance share a persistent lifecycle lock. See
[archive format and verification](recovery-archive.md). Complete snapshot-set
creation is implemented under a confirmed offline maintenance window, with
protocol-owned identity inventory and explicit external dependencies. Controlled offline preview/activation, identity decisions, durable transaction
rollback and real CLI server startup/failure/crash drills are now implemented.
Successful file activation remains awaiting_startup until the actual database,
inbound/Gateway and local HTTPS listener checks pass. Windows activation and
embedded-host lifecycle integration remain pending.

Managed local/S3 full-archive scheduling, history, verification, download and
retention now extend the same Backup owner; see [managed backups](managed-recovery-backups.md).
Web archive import and authenticated preview now reuse that owner and verifier.
Web restore activation and recent-result presentation are available on the supported systemd host; protected update recovery now uses the same collector and installed-service supervision. Legacy S3 restore now refuses
active database owners before downloading; its offline compatibility path imports
configuration into a private copy of the local store and uses the same controlled
activation/startup journal, preserving local identities. It no longer renames a
foreign database over live SQLite connections.
Existing update rollback restores executable bytes only.
Database startup now rejects future/foreign/gapped migration histories and
metadata mismatches before bootstrap/journal-mode changes, sharing the archive
verifier's migration-prefix check. It does not make older unguarded executables
safe by themselves; protected update coordination also validates the target receipt capability.

## Stage 3 — certificate lifecycle (in progress; not exposed yet)

The internal foundation now implements stable resource/private account storage
in schema 24, revision/lease and deletion-reference protection, real HTTP-01
issuance through x/crypto/acme, account reuse, exact SAN/chain validation and an
atomic TLS cache. A local HTTPS CA verifies the actual JWS, HTTP proof and CSR;
tests exercise renewal and continued traffic on an established TLS stream.
See [implemented behavior and remaining integration](managed-certificates.md).
The follow-up implements the real Cloudflare adapter and durable owned-record
cleanup, TXT propagation checks, a single bounded persistent renewal/backoff
worker, manual rate protection, cancellation and restart/lease recovery. Clone
recovery disables certificate jobs and removes source private keys, DNS tokens
and cleanup receipts. Local CA/provider, injected-clock, race and real encrypted
restore tests cover these components. Production network/worker assembly,
listener adapters, live ARI, permissions/RPC, frontend and complete application
restart/failure qualification are still missing.

Extend pkg/cert and existing management/gateway TLS with stable managed-resource
IDs and hot-reloaded verified certificate snapshots. Keep site certificates,
management HTTPS, Gateway termination, Gateway MITM CA and TLS Auto CA distinct.
Use a mature ACME client, HTTP-01 and real DNS-01 (Cloudflare provider), safe
account/provider-key persistence, bounded renewal/retry scheduling, restart
recovery, deletion-reference checks and UI alerts. Test against local ACME CA
and DNS provider servers without depending on public ACME services.

## Validation notes for the first delivery

Focused packages and race tests pass; golangci-lint v2.15.0 reports zero issues.
Go formatting/go-fix and frontend lint/typecheck/i18n/style/build gates pass.
Frontend full suite: 102 files / 305 tests.

The first `go test ./...` run exposed an unchanged NAT lifecycle test timing
failure (`TestTableCleanerSleepsWhenEmptyAndRestarts: idle source not removed`).
That test passed 25 consecutive isolated runs, and the subsequent full suite
passed. No NAT behavior was changed in this component delivery.

Benchmark details and exact reproduction command are in
[intelligent selectors](intelligent-selectors.md). Results are runtime selection
microbenchmarks, not end-to-end physical-link qualification.

The component commits passed backend full/race tests and lint, frontend tests
and browser checks. The consolidated PR heads run their complete CI again; use
the current checks on the two active PRs for delivery status rather than checks
on the superseded component PRs.

The previous lite-client cold-Tailscale fixture failure was reproduced on main
and its DERP-registration repair passed local repeated/race and remote checks.
Main #628 subsequently restored the tsnet adapter and replaced that fixture.
This branch now retains the current tsnet transport/DNS fixture and adapts
native observations without LocalAPI/network calls or extra status workers.
The historical lite-fixture qualification is not a current-tsnet validation claim.
See [local Tailnet readiness](network-diagnostics.md#local-tailnet-integration-fixture-readiness).

Chrome fallback coverage verifies Selector/circuit and monitoring views at
1440, 360 and 320 px; CI retains the resulting screenshots.

## Circuit follow-up validation

The backend extends existing selector and observation JSON; no new SQLite
migration is needed beyond schema 19. The frontend adds circuit controls and
evidence details in EN/JA/KO, preserving manual behavior. Frontend gates pass
with 104 files / 309 tests. Backend full tests, lint and focused race coverage
pass. Measurements and exact reproduction commands accompany this delivery.

## Probe policy follow-up

The fixed candidate egress now uses existing route block/DNS/rule identities and
stream/datagram governors with live global/default/route shaping. Startup policy
readiness gates construction and budget spend. See [measurement policy](probe-policy.md)
for actual scope, lifecycle behavior, tests and the remaining overhead-budget
qualification. Existing monitoring status JSON adds `policyState`; schema remains
19. Frontend EN/JA/KO explains waiting/enforced/standalone measurement scope.

## Measurement bounds follow-up

Manual and periodic measurements share global admission and cancellation. Active
download reservations include bounded Node-stream TLS/HTTP/read-ahead overhead;
schema 20 preserves legacy usage without guessing its unrecorded overhead. The
existing Prometheus endpoint gains finite-label selector/circuit/probe/speed
metrics without database work on scrape. Frontend EN/JA/KO displays shared slot
use and inclusive budget semantics. See [measurement bounds](measurement-bounds.md).

Stage 1 remains in progress, including final resource/transport qualification.
Stage 2 transfer/archive/offline CLI recovery is implemented; broader Stage 2 hosts, plaintext point retention/periodic drills and Stage 3 remain pending.

Native session adapters and periodic login protection now use existing protocol
state and the same node/selector runtime. See the native session section in
[outbound observability](outbound-observability.md#native-session-evidence) and
[periodic VPN reuse](probe-policy.md#periodic-work-reuses-established-vpn-sessions).
They require no SQLite migration beyond schema 20. Frontend lifecycle descriptions
remain separate from channel/target health. Full three-stage completion is pending.

## Offline restore qualification

The restore transaction validates authenticated inventory, platform/schema and
instance confirmations before any replacements. Original mode explicitly warns
about credential revocation/quota rewind; clone mode resets management/native
machine identities and disables restored resources and S3 schedules. Referenced
external files are confined and rebound. See [operator workflow and limits](recovery-archive.md).
Fault injection covers every replacement boundary, interrupted rollback and real
CLI process death. Local RSS and allocation measurements distinguish age's
per-chunk cumulative allocation from bounded live streaming memory; commands,
fixture scope and raw data are documented. The archive and restore additions
introduced no SQLite migration beyond 20; managed full backups subsequently add
schema 21, imports add 22 and exclusive restore admission adds 23. Windows/embedded coordination remains
incomplete; managed scheduling and retention are described below.

The offline-restore change passes full Go tests, eight-package focused race
coverage, modernc plus mattn/fts5, gofmt/go fix, golangci-lint v2.15.0 (zero
issues), actionlint and build-script shellcheck. Frontend contract synchronization
passes lint, typecheck, all 17 translation namespaces, style audit, build and
105 files / 314 tests. A local full-test attempt using a long custom build temp
path exceeded the pre-existing Unix socket test's pathname limit; that test and
the full suite pass using the default temporary directory. Remote checks for
this change are authoritative only after publication on the two active PR heads.

## Managed full backups

Migration 21 extends the existing BackupStore with bounded history and atomic
job transitions. The existing scheduler can request confirmed maintenance,
create full public-key encrypted archives, resume S3 uploads after restart,
verify ciphertext readback, protect downloads and apply owned retention. The
Backup UI exposes the real settings/history/create/verify/download/retry/delete
flows in EN/JA/KO. Scheduled work does not depend on the browser. Automatic
maintenance currently targets root-owned Linux systemd deployments; other hosts
retain offline tools pending complete service coordination. An isolated real
systemd/HTTPS/S3/helper-crash drill now accompanies hermetic tests. See
[managed backups](managed-recovery-backups.md) for exact behavior and limits.

Broader platform maintenance, plaintext recovery-point retention, periodic
restoration drills and ACME remain outstanding. The three-stage goal is active.

The managed-backup UI has automated 1440/360/320 px interaction/screenshot
coverage for maintenance confirmation, actual draft save, history and the private
verification dialog, with zero horizontal overflow. Those fixtures are explicitly
synthetic; the isolated systemd/HTTPS/object-server drill proves the real
stop/capture/restart/verification/crash behavior separately. Finite backup state,
latest complete-point timestamps and download leases now use atomic metric
snapshots with no SQLite work on scrape.


## Web recovery preview

Backup responsibilities have distinct owners:

- `pkg/app/backup`: one scheduler and operation lease, managed jobs, transfers,
  retention, metrics and expiring Web import records.
- `pkg/app/backup/recovery`: deployment inventory and snapshots, authenticated
  restore planning, file activation, startup validation and rollback.
- `pkg/store/backup`: existing SQLite settings, history, import records and
  recorded startup inputs.
- `pkg/store/backup/archive`: encryption, versioned streaming format, confined
  plaintext staging and authenticated manifest/database validation.

The scheduler consumes an opaque prepared import plan rather than constructing
or interpreting file transactions. Shared filesystem and snapshot rules are
internal packages, with one source of truth for permissions, path confinement,
space limits and runtime-table policy. Tests and benchmarks live beside their
owners; deployment fixtures are shared only by tests. Application assembly
injects the optional maintenance interface rather than the whole AppInstance;
actual application-owner readiness checks remain in `pkg/app/recovery_health.go`.
The desktop host also separates recovery and update responsibilities:

- `cmd/yuhaiin/internal/recovery`: offline command parsing, private input files
  and maintenance helper commands; it does not assemble the application.
- `cmd/yuhaiin/internal/update`: installed-platform updater adapters and helper
  commands; the update engine remains in `pkg/update`.
- `cmd/yuhaiin/internal/servicehost`: installed-service ownership and shared
  systemd/launchd operations used by backup, updates and service commands.
- `cmd/yuhaiin/internal/startuphealth`: pinned local listener readiness and
  recording the host's actual startup inputs.

`main` dispatches commands and wires these owners. Unit tests live beside the
implementation. Tests that exercise the actual server assembly and its shutdown
remain in the command package. The isolated systemd drill compiles the
`internal/servicehost` tests; CI includes `./cmd/yuhaiin/...` so moved tests keep
running. Release builds target `./cmd/yuhaiin` explicitly: building a multi-package
pattern without `-o` would check packages without emitting the executable. SQLite snapshot code stays with its database owner rather than gaining
a second database implementation.

The SQL schema, archive format, management contracts and lifecycle ownership are
unchanged by this refactoring.

Migration 22 adds expiring, principal-bound import records to BackupStore.
Encrypted uploads and original/clone previews reuse the existing archive codec
and replacement planner, with bounded traffic/disk/memory, transient decryption
input and private staging cleanup. The existing Backup page exposes actual
upload, preview and confirmed discard operations in EN/JA/KO. Real HTTPS
service and responsive browser checks cover these operations. See
[import lifecycle and limits](managed-recovery-backups.md#web-archive-import-and-authenticated-preview).
Web activation now uses exact-preview consent, sealed projected files and the existing controlled startup/rollback transaction on root-owned Linux systemd hosts.

The offline restore CLI now offers explicit startup-input adoption. Its existing
transaction/result records retain relocated TLS/auth/listener/file inputs through
commit, repeated real process restarts, failed subsequent restores and interrupted
startup. A previous adopted binding is restored with its original inodes. The
BackupManage-protected status API and existing Backup page show the latest actual
commit/rollback result. Local service drills exercise file certificates and web
assets against deliberately incompatible host flags; original flags remain the
default without an opted-in restore. See
[startup and rollback](recovery-archive.md#activation-real-startup-and-rollback).
The Web activation request now persists exact-preview identity confirmations and hands off to an independent installed-service helper. Migration 23 serializes admission; its startup checks and crash fallback reuse this integration. See the [confirmed Web workflow](managed-recovery-backups.md#confirmed-web-activation).

## S3 archive retrieval

Verified S3 history items support explicit streamed local retrieval/repair through
the existing backup lease and governed S3 proxy, with size/SHA-256 checks before
publication, finite time/byte/disk budgets, cancellation and interrupted-transfer
cleanup. The UI distinguishes local presence, retrieval evidence and authenticated
archive checks. Exported public history metadata plus an owner-only S3 settings
file also enable `recovery fetch` without opening deployment databases.
[Workflow and measurements](managed-recovery-backups.md#recover-a-missing-or-damaged-local-s3-copy).
These retrieval operations share the backup owner used by protected updates;
ACME remains required.

## Update target compatibility

Published release assets now include checksum-bound schema/CPU manifests generated
on the build host without running the target binary. Update admission, downloaded
bytes and privileged helpers are checked independently against actual read-only
live-WAL schema catalogs; history preserves only proven self-binary capabilities.
Unknown/incompatible binary rollback is refused, and the UI shows current/target
schemas and actual recovery readiness. No SQLite migration is required.

Root-owned Linux systemd updates now create a full encrypted point before binary
replacement, pin that point while unresolved, and require an operation/digest/PID
bound receipt after actual application/listener readiness. A potentially migrated
failed target remains stopped for explicit paired offline recovery; no old binary
is silently started against new stores. The public status/cancellation/offline CLI
and EN/JA/KO confirmation/result UI use the same ownership model. The real service
runner adds a real next-schema success, post-migration startup failure, helper
SIGKILL and actual source-schema CLI recovery. It derives both versions from
the build's catalog (originally 23 to 24); no production migration/fault hook is added.
Release descriptors declare the independent startup-receipt capability. See
[workflow, tests and resource scope](update-rollback.md#protected-update-and-offline-recovery).

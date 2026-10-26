# Enterprise reliability delivery

This work is based on backend main `364afb0f` and frontend main `391e4db`.
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
- Independent TCP/UDP evidence extending existing node observability.
- Six strategy calculations, fresh comparable RTT and active-capacity semantics.
- Hysteresis, hold/cooldown, sticky failover, manual lock and explicit fallback.
- Precomputed immutable snapshots and weighted new-connection admission.
- Candidate deletion protection and node/Set/endpoint dependency-cycle checks.
- Verified, streaming, bounded manual download tests with durable daily budget.
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

The full encrypted archive, maintenance/offline consistency, retention,
restore preview/CLI/UI and update recovery integration remain required.
`Backup.restoreStateDB` still renames over a live database and removes WAL/SHM;
this legacy restore path is not a completed safe recovery implementation.
Existing update rollback restores executable bytes only.

## Stage 3 — certificate lifecycle (pending)

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

The previous cold-Tailscale failure was reproduced on main. Its local fixture
waited for a control route before the receiving client had finished registering
at the test DERP server. The fixture now waits for both real registrations,
without warming the peer connection or relaxing its two-second assertion.
The ordinary and release-tag Tailnet package suites passed three repetitions;
a mixed-STUN race batch passed all 20 cold IPv4 TCP scenarios. The standalone
repair passed all remote checks before being folded into the backend entry.
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
Stage 2 transfer prerequisites are implemented; full recovery and Stage 3 remain pending.

Native session adapters and periodic login protection now use existing protocol
state and the same node/selector runtime. See the native session section in
[outbound observability](outbound-observability.md#native-session-evidence) and
[periodic VPN reuse](probe-policy.md#periodic-work-reuses-established-vpn-sessions).
They require no SQLite migration beyond schema 20. Frontend lifecycle descriptions
remain separate from channel/target health. Full three-stage completion is pending.

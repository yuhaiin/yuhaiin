# Enterprise reliability delivery

This work is based on backend main `364afb0f` and frontend main `391e4db`.
It does not depend on the open enterprise identity/resource/security stacks
(backend #618/#620/#621, frontend #530/#532/#533).

The authorized scope contains three complete stages, each with backend/frontend,
persistence, tests, resource measurements, documentation and separate PRs.
A component delivery below does not complete the overall scope.

## Stage 1 — intelligent outbound selection (in progress)

First backend/frontend delivery: [backend #622](https://github.com/yuhaiin/yuhaiin/pull/622),
[frontend #535](https://github.com/yuhaiin/yuhaiin-react/pull/535). Both remain draft
while the complete Stage 1 scope is being implemented.

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
- Complete transport-overhead qualification of throughput budgets; routing,
  stream/datagram admission and live shaping now use existing app components.
- Selector Prometheus metrics and bounded reason labels.
- Shared manual/periodic probe admission and strict active-test transport-overhead
  reservations, alongside existing scheduler and payload bounds.
- Final qualification of worst-case churn/snapshot/resource measurements and
  broader real-transport connection benchmarks. Deterministic TCP/UDP creation,
  loopback TCP and 1,024 concurrent admission tests are now present.
- Browser desktop/mobile verification and required remote CI verification.

## Stage 2 — disaster recovery and safe updates (pending)

Reuse existing app/store Backup and S3 code. Inventory data ownership first:
configuration state SQLite, management auth SQLite when enabled, management TLS
bundle, gateway CA in state DB, and protocol-owned identities. Avoid copying the
whole data directory. Use coherent SQLite snapshots and an explicit coordinated
maintenance/offline mode for cross-database consistency. Build a versioned,
streaming authenticated-encrypted archive with staged verification/restoration,
rollback recovery points, retention, S3 download verification and offline CLI.
Integrate update/schema compatibility and real restore/startup fault injection.

Observed existing paths to address: `Backup.restoreStateDB` renames over a live
database and removes WAL/SHM, `snapshotStateDB` reads the whole snapshot into
memory, ticker replacement leaves stopped-channel readers behind, and S3 methods
do not currently propagate their context to requests. These are not fixed by
Stage 1. Existing update rollback restores executable bytes only.

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

Remote validation: frontend #535 build (23.x) passed. Backend #622 initially
failed only the existing Tailscale cold-peer regression (5.17-second first TCP
connection, threshold 2 seconds). The same issue reproduced in 3 of 10 local
race runs of TestLocalTailnet; the tested package has no dependency on node or
latency runtime changes, and the Tailscale source/dependencies are unchanged.
The failed-job CI rerun passed; backend #622 now has 44 successful checks and
nine expected skips. This pre-existing intermittent transport
problem must remain visible in qualification; no test threshold was relaxed.

Browser plugin discovery returned no connected browser. The subsequent Chrome
fallback verified Selector/circuit and monitoring views at 1440, 360 and 320 px;
frontend #537 CI also runs that harness and retains screenshots.

## Circuit follow-up validation

The backend extends existing selector and observation JSON; no new SQLite
migration is needed beyond schema 19. The frontend adds circuit controls and
evidence details in EN/JA/KO, preserving manual behavior. Frontend gates pass
with 104 files / 309 tests. Backend full tests, lint and focused race coverage
pass. Measurements and exact reproduction commands accompany this delivery.

Monitoring PR #623 currently has a failed no-legacy-stack check: the unchanged
Tailscale cold-peer test again takes roughly five seconds against its two-second
limit. The dependency-boundary assertions and monitoring-specific CI pass. A
failed-job rerun reproduced the transport failure; it is not treated as green.

## Probe policy follow-up

The fixed candidate egress now uses existing route block/DNS/rule identities and
stream/datagram governors with live global/default/route shaping. Startup policy
readiness gates construction and budget spend. See [measurement policy](probe-policy.md)
for actual scope, lifecycle behavior, tests and the remaining overhead-budget
qualification. Existing monitoring status JSON adds `policyState`; schema remains
19. Frontend EN/JA/KO explains waiting/enforced/standalone measurement scope.

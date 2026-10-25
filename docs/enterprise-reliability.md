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

The follow-up branch propagates cancellation through HTTP, DNS/DoQ, STUN and IP
probes, with local cancellation tests. Its scheduler integration is still pending.

Still required before Stage 1 is complete:

- Shared cancellable/deduplicated scheduler, global defaults/selector overrides,
  network-cost/mobile policy, network-change rescheduling and native-state probes.
- Explicit TCP-connect probe, controlled periodic throughput tests and detailed
  measurement/event history.
- Full Closed/Open/Half-open circuit breaker with bounded trial quotas and
  protocol-aware failure classification, including lazy VPN establishment.
- Accurate integration with existing traffic-control admission/limits.
- Selector Prometheus metrics and bounded reason labels.
- Complete UI controls for those scheduler/breaker/periodic features.
- Actual TCP/UDP connection creation benchmarks, 1,000+ concurrent connections,
  worst-case churn/snapshot/resource measurements and Android compilation/default tests.
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
A failed-job CI rerun is in progress. This pre-existing intermittent transport
problem must remain visible in qualification; no test threshold was relaxed.

Browser plugin discovery returned no connected browser. Visual browser checks
are still required; component tests do not substitute for those checks.

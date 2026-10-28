# Enterprise reliability completion audit

The original scope is all three stages, with backend/frontend, persistence,
security, resource qualification, documentation and exact-head CI. This document
records verified implementation evidence and concrete gaps; a passing test does
not prove requirements beyond what that test actually exercises. The overall goal
is not complete.

## Stage 1: findings from current implementation

| Requirement | Current authoritative evidence | Status / remaining work |
| --- | --- | --- |
| 1.1 Six opt-in Selector modes; legacy manual NodeID | `pkg/contract/node/selector.go`, `pkg/node/selection.go`, `selector_runtime.go`; `TestSelectionStrategiesAndManualCompatibility` | Implemented; final full UI/configuration audit still required. |
| 1.1 Candidate enable/priority/weight, preferred/lock, TCP/UDP and fallback | Existing policy/status contracts and precompiled runtime; `TestFailoverRecoveryFallbackAndNetworkSeparation`, weighted/disabled and circuit fallback tests | Implemented paths exist; verify all serialized defaults and editor round trips against the original specification. |
| 1.2 Distinct construction/channel/remote/HTTPS/native evidence | `health_evidence.go`, `native_status.go`, `observability.go`; native and cancellation tests | Implemented and hermetically tested. The selector guide enumerates OpenVPN, GlobalProtect, L2TP, SoftEther and Tailnet providers and their cached-session/control/static-mode limits; other or interface-hiding chains use end-to-end evidence without invented native health. |
| 1.3 Shared bounded scheduler, cancellation, Android/cost/native-login rules | `probe_scheduler.go`, `monitoring.go`; scheduler hard-bound/dedup/timeout/class/cooldown tests and monitoring/native lifecycle tests | Implemented. Worst-case deployment resource/churn qualification remains to be refreshed against the final state. |
| 1.4 Fresh comparable RTT, EWMA, dual hysteresis, hold/cooldown | `selection.go`; expiry, latency hysteresis, failover/recovery and network separation tests | Implemented, including preferred-return control for latency/speed/balanced modes, unchanged manual behavior and weighted distribution. Pure strategy tests cover sticky/allowed return, metric eligibility, thresholds, hold, emergency failover and third alternatives; a persisted-runtime test covers real admission, an existing stream and suppression metrics. Final resource/UI qualification remains. |
| 1.5 Passive business traffic separate from active measured capacity | `RuntimeStatus.UploadBps/DownloadBps`, volatile `TrafficWindow`, bounded `recentTcpDials` versus `ThroughputMeasurement`; deterministic rate/idle-SQL/restart tests and Node overview | Current/window observed traffic, active target/time-specific Mbps and retained TCP dial failures are implemented separately. No rate window enters capacity ranking. Full final UI/configuration/resource qualification remains required. |
| 1.5 Bounded verified download tests and durable inclusive budget | `pkg/net/latency/throughput.go`, `pkg/node/speed.go`, measurement admission/budget tests; schema 20 | Implemented for both directions with opt-in upload protocol; no background test is enabled by creating a selector. |
| 1.5 / 1.6 Upload tests and useful upload-weight policy | `latency/upload.go`, existing `NodeRuntime.Speed`, per-direction persisted counters, shared scheduler/budget; `TestUploadRuntimeLocalTLS`, protocol/expiry/budget/schedule tests and React upload controls | Implemented with explicit endpoint consent and validated byte-count acknowledgement. A separate bounded HTTPS endpoint tool is provided. Exact-head CI and final specification qualification remain required. |
| 1.6 Normalized balanced components and explanations | Existing score weights/components/status contracts and selection tests | Download/upload/latency/stability components exist with independent sample provenance/freshness. Audit invalid/missing/expired metrics and presets against the original examples. |
| 1.7 Circuit Closed/Open/Half-open, quotas, no request replay | `circuit.go`, `circuit_binding.go`; circuit/connection/observability tests, `TestSelectorSwitchDoesNotReplayOrCloseEstablishedStream` | Neutral cancellation/close/QUIC, local quota/policy and reconfiguration outcomes now share classification across generic counters, construction and channel evidence; nested policy wrappers are covered. Complete the remaining protocol/error-classification matrix and actual UDP session behavior audit. |
| 1.8 Atomic configuration/runtime snapshots; no SQLite on admission | `config_generation.go`, `selector_runtime.go`; `TestSelectorConnectionPathDoesNotQuerySQLite`, 1,024 creators during churn | Implemented and qualified with manual/automatic TCP/UDP admission, 100/1,000-candidate ranking, 1,024 creators during churn and before/after full-history heap/allocation/goroutine lifecycle fixtures. Shared 10-Selector results, read-cache memory tradeoff and cumulative compilation cost are explicit in the selector guide; these are not native VPN/WAN or maximum deployment capacity evidence. |
| 1.9 Existing React editor, raw evidence/score/reasons/history | Selector/Nodes editor and real-browser harness at 1440/360/320 px | Download/upload controls, explicit consent, independent schedule settings and direction-labeled history are implemented. Final requirement-by-requirement UI audit remains. |

The upload path extends the existing counters, 16-sample history, shared scheduler,
admission and durable daily budget. It does not copy passive business Bps into
capacity or use a download timestamp to validate an upload. Ordinary endpoints
receive no test POST unless they explicitly advertise the configured protocol.
Measurement and scoring tests do not replace the remaining protocol, resource
and complete UI qualification above.

## Stage 2: verified delivery and remaining qualification

Existing app/store backup owners provide age-encrypted versioned streaming full
snapshots, coordinated stopped-writer SQLite sets, confined staged authentication,
explicit original/clone identities, journaled activation/rollback, startup input
binding, local/S3 schedules/history/retention, bounded archive retrieval/repair,
Web import/preview/activation and public offline commands. Their dedicated
archive/recovery/transfer/service tests and resource evidence are documented in
`recovery-archive.md`, `managed-recovery-backups.md` and `backup-recovery.md`.

Protected update delivery at backend b97d5e5d / frontend a99e39e adds target
receipt capability checks, client-operation/digest binding, existing encrypted
collector reuse before executable replacement, source history/schema retention,
private durable journal, independent service/PID/pinned-listener verification,
SIGKILL fallback and explicit paired offline recovery. Original-instance ID,
archive ID and source digest must match; an arbitrary clone is not the recovered
source. Required local points are pinned while unresolved. S3 upload/readback is
separate and resumes after service recovery. Actual systemd/HTTPS tests exercise
schema-24 success, committed-migration startup failure, fenced helper kill and
public CLI recovery to schema 23. No production migration/fault hook is added.

Still qualify/complete:

- Broader automatic service-maintenance/update supervision hosts; root-owned
  Linux systemd is the implemented automatic path. Other hosts must not be
  advertised as having the same automatic recovery capability.
- Plaintext pre-restore recovery-point retention and optional periodic automated
  restoration drills, with key/identity ownership and resource bounds.
- Large-instance activation/update resource/downtime qualification and a complete
  fault/compatibility/permissions audit against every original Stage 2 item.
- Exact-head remote CI. Earlier green commits do not prove a later revision.

No new SQLite migration beyond 23 is required for protected updates: existing
backup JSON contains the additive policy/point flags; the bounded private update
journal contains operation state. Archive and management identity schemas stay
unchanged. This observation is not a substitute for migration compatibility tests.

## Stage 3

ACME/certificate lifecycle remains unimplemented in this work. Stable managed
certificate references, HTTP-01, a real DNS-01 provider, safe account/provider-key
persistence, renewal/backoff/deduplication, verified hot replacement,
Management/Gateway integration, reference protection, EN/JA/KO UI and deterministic
local-CA/provider tests are all still required. Existing management TLS, site
termination, MITM CA and TLS Auto CA must retain their distinct ownership.

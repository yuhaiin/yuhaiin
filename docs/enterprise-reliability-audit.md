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
| 1.2 Distinct construction/channel/remote/HTTPS/native evidence | `health_evidence.go`, `native_status.go`, `observability.go`; native and cancellation tests | Implemented and hermetically tested; protocol coverage must be enumerated rather than inferred from the interface. |
| 1.3 Shared bounded scheduler, cancellation, Android/cost/native-login rules | `probe_scheduler.go`, `monitoring.go`; scheduler hard-bound/dedup/timeout/class/cooldown tests and monitoring/native lifecycle tests | Implemented. Worst-case deployment resource/churn qualification remains to be refreshed against the final state. |
| 1.4 Fresh comparable RTT, EWMA, dual hysteresis, hold/cooldown | `selection.go`; expiry, latency hysteresis, failover/recovery and network separation tests | Implemented. Confirm final controls and preferred-return semantics for each mode. |
| 1.5 Passive business traffic separate from active measured capacity | `RuntimeStatus.UploadBps/DownloadBps` versus `ThroughputMeasurement`; `TestSelectionExpiresAndNeverInventsCapacity` | Separation is implemented. Explicit passive window-average presentation still needs a requirement-level audit. |
| 1.5 Bounded verified download tests and durable inclusive budget | `pkg/net/latency/throughput.go`, `pkg/node/speed.go`, measurement admission/budget tests; schema 20 | Implemented for downloads. No background test is enabled by creating a selector. |
| 1.5 / 1.6 Upload tests and useful upload-weight policy | `SpeedTestRequest` has URL/byte/time/daily limits but no upload mode; `NodeRuntime.Speed` only calls `MeasureDownload`; documentation currently tells operators to leave upload weight/minimum at zero | **Functional gap.** Upload weights/minimums are exposed, but the instance cannot produce active upload measurements. Implement an explicitly supported HTTPS upload endpoint protocol, shared hard budgets/admission/policy/cancellation, separate per-direction freshness/smoothing and real UI/tests before treating upload-oriented balanced selection as usable. Ordinary endpoints must never receive an unsolicited test POST. |
| 1.6 Normalized balanced components and explanations | Existing score weights/components/status contracts and selection tests | Download/latency/stability components exist. Upload scoring is blocked by the measurement gap above. Audit invalid/missing/expired metrics and presets against the original examples. |
| 1.7 Circuit Closed/Open/Half-open, quotas, no request replay | `circuit.go`, `circuit_binding.go`; circuit/connection/observability tests, `TestSelectorSwitchDoesNotReplayOrCloseEstablishedStream` | Implemented paths exist. Complete the protocol/error-classification matrix and actual UDP session behavior audit. |
| 1.8 Atomic configuration/runtime snapshots; no SQLite on admission | `config_generation.go`, `selector_runtime.go`; `TestSelectorConnectionPathDoesNotQuerySQLite`, 1,024 creators during churn | Implemented and tested. Refresh final 100/1,000-candidate, TCP/UDP, churn, heap/allocations/goroutine evidence; microbenchmarks are not VPN/WAN capacity evidence. |
| 1.9 Existing React editor, raw evidence/score/reasons/history | Selector/Nodes editor and real-browser harness at 1440/360/320 px | Implemented download-oriented flow. Upload controls/results and final requirement-by-requirement UI audit remain. |

The upload gap cannot be closed by copying passive UploadBps into capacity,
accepting an operator's theoretical bandwidth, using a stale download timestamp
for upload validity, or leaving a configurable but unusable scoring weight.
Existing counters, sample history, scheduler and admission/budget owners must be
extended rather than introducing a second measurement/statistics subsystem.

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

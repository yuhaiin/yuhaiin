# Enterprise reliability

Review uses one PR per repository, both targeting `main`:
[backend #622](https://github.com/yuhaiin/yuhaiin/pull/622) and
[frontend #535](https://github.com/yuhaiin/yuhaiin-react/pull/535).
The implementation extends existing owners and does not depend on the unmerged
enterprise identity/resource/security stacks. The backend includes main through
`293aa065` and the frontend includes main through `adf2322`. This PR adds no
Controller/Agent, Raft, distributed state, WAF or VPN protocol; SSTP server
support is inherited from main.

This document describes the current result, rather than a chronological list of
component PRs. The [requirement matrix](enterprise-reliability-audit.md) records
implementation/test evidence, qualification boundaries and delivery gates.
Current commit checks on the two PRs are authoritative for remote CI; an older
green commit does not qualify a later revision.

## Intelligent outbound selection

Legacy `nodeId` selectors remain manual. Explicit policies enable failover,
lowest latency, measured download throughput, normalized balanced scoring or
weighted new-flow distribution. Candidates have independent enable/priority/
weight settings, preferred-return policy, manual lock and explicit unhealthy/
unknown fallback. Decisions and health continue without an open browser.

The existing Node Runtime retains independent TCP/UDP construction, channel,
remote-response, HTTPS/DNS and supported native-session evidence. Shared bounded
probe scheduling applies cancellation, jitter, thresholds, cooldown, network and
Android/cost policy. Closed/Open/Half-open circuits have finite trial quotas.
Unknown/expired measurements never mean zero RTT or unlimited capacity. RTT
switches require both absolute and relative improvement, hold and cooldown.

Active download/upload tests use the chosen Node, verified HTTPS and independent
sample freshness/smoothing. Byte/time/concurrency and durable daily budgets are
hard bounded. Upload additionally requires explicit endpoint support and consent.
Current/window business Bps is load, not capacity. Timeout ratios derive from the
same fresh health window, with separate outcome and comparable-RTT sample counts;
they are not UDP packet-loss estimates.

Compiled immutable snapshots keep scoring/probes/SQLite off packet and ordinary
connection paths. New flows choose a candidate; established TCP/UDP references
stay pinned. A remotely accepted POST is not replayed after transport failure.
Normal HTTP 4xx, cancellation, close, policy/quota rejection and ordinary QUIC
cancellation do not condemn a Node. Deletion/reconfiguration uses references,
cycle detection and runtime generations, without rebuilding unrelated routes.

The existing EN/JA/KO Selector/Nodes interfaces expose actual policy saves,
manual tests, independent schedules, raw evidence/components/reasons and bounded
history. See [selection](intelligent-selectors.md),
[observation semantics](outbound-observability.md) and
[measurement limits](measurement-bounds.md).

## Recovery and protected updates

Configuration export remains distinct from a full deployment archive. Existing
Backup/SQLite/S3 owners provide coherent stopped-writer multi-database/file
inventories and streaming age AEAD encryption with an external recipient or
passphrase KDF. Private manifest/staging, schema/path/size validation and explicit
original/clone identity decisions precede durable activation/rollback. Real
service/database/listener checks decide startup commit; copying files or calling
systemctl Start does not establish recovery success.

The Backup page manages local/S3 schedules, history, verified streaming transfer,
download/retrieval, sealed previews and confirmed activation on the supported
service host. The CLI supports creation, fetch, verification, preview, restore,
rollback and independent default-off plaintext rollback-copy pruning. Active,
latest/committed and configured file dependencies remain protected. Clone
recovery removes source machine/account credentials and disables inherited
maintenance, cleanup, monitoring and certificate jobs.

Full capture checks destination space before each WAL-aware SQLite snapshot,
identity/dependency copy and final encrypted output while plaintext staging still
exists. Checks preserve the existing 256 MiB reserve and account for manifest/
AEAD framing. They are filesystem admission checks, not reservations against
unrelated concurrent disk consumers. Failures retain the source and remove owned
partial output before binary replacement can proceed.

Protected updates validate target checksum/schema/capabilities, create an encrypted
recovery point, retain source binary/schema and independently verify service PID
and pinned HTTPS readiness. Failed migrated targets stay stopped for reviewed
paired binary/database restoration; old executables never silently open newer
schemas. Irreversible migrations do not promise automatic database rollback.

Automatic disruptive maintenance is qualified on root-owned Linux systemd and
lingering systemd user services. Standalone, launchd, Windows and embedded automatic supervision is
not claimed. Offline tools and their platform-specific durability limitations
are explicit in the guides. Optional periodic automated restoration drills are
not implemented. These must not be confused with the real hermetic/service crash
tests that are implemented and run in CI.

See [data ownership](backup-recovery.md), [archive/CLI](recovery-archive.md),
[managed backups](managed-recovery-backups.md) and [safe updates](update-rollback.md).

## Managed HTTPS certificates

The existing certificate owner now manages stable site resources, private ACME
accounts/DNS providers, HTTP-01 and Cloudflare DNS-01, exact-record cleanup,
persistent bounded renewal/backoff and verified atomic TLS replacement. One
worker/timer and durable leases supply restart recovery/deduplication. Failed
issuance or metadata refresh retains an existing valid certificate.

Gateway TLS termination references managed resources with SNI/SAN/expiry checks
and transactional deletion guards; new handshakes see renewed material while
existing streams continue. HTTP-01 explicitly uses an opted-in existing port-80
Gateway after its source ACL. Management HTTPS supports host-owned
`-https-certificate-id`, current validity checks, deletion references and hot
renewal, with no remote plaintext fallback. Self-signed/file defaults and the
independent MITM/TLS Auto CAs remain compatible.

Live CA renewal advice (ARI) uses governed verified HTTPS, bounded origin-fenced
responses and the existing worker/lease/status persistence. Optional ACME
`newOrder replaces` is not exposed by the mature client; no CA-specific rate
exemption is claimed. The EN/JA/KO Certificates page provides real mutations,
write-only DNS credentials, lifecycle/reference alerts and manual renewal.
See [certificate lifecycle](managed-certificates.md).

## Ownership, persistence and qualification

- `pkg/app/backup` owns scheduling/transfers; `recovery/` owns inventories,
  staging, activation, rollback and local copies. Application assembly/readiness
  stays with the app. There is no parallel backup or certificate subsystem.
- `pkg/store/backup` owns records; `archive/` owns the encrypted format. Recovery
  contracts and CLI/service supervision have dedicated packages.
- Configuration migrations 18/19/20 add selector policy, monitoring and durable
  measurement budgets; 21/22/23 add backup history/import/admission; 24 adds
  private certificate/account/provider/cleanup/reference tables. Configuration
  export excludes identity/certificate secrets and history. Full snapshots
  include required private state. Derived timeout rates and cleanup policy add
  no schema migration.
- Deterministic clocks, local HTTP/TLS/DNS/provider servers, real WAL stores,
  race tests and isolated systemd migration/crash/restore tests cover the named
  safety properties. Chrome at 1440/360/320 px covers the actual existing UI.
- Reports retain manual/automatic TCP/UDP admission, 100/1,000-candidate ranking,
  1,024 concurrent creators, snapshot churn, heap/allocation/goroutine lifecycle,
  streamed archive/restore memory, and actual 1/64/256 MiB service maintenance.
  Each report states its fixture and limits; local results are not WAN/native
  VPN capacity guarantees.

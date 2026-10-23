# User traffic statistics and audit

The server records user usage when its proxy authentication provider is enabled.
It uses the existing SQLite state store; it does not need DuckDB or an external
metrics service. Core-only/native Android configurations leave the recorder off.
The React companion exposes the reports under **Account & security**.

## What is counted

- Upload/download payload bytes, lifetime and selected UTC period, plus hourly,
  daily and monthly traffic series. Numeric counters are decimal strings in JSON.
- First observed session and last observed traffic; current sampled transfer rate;
  current and peak TCP/UDP sessions; successful opens and failures/rejections.
- Active minutes: one minute per user when payload activity is observed, deduplicated
  across credentials and parallel sessions. This is approximate at minute boundaries.
- Combined session duration: sum of elapsed session time, including idle time and
  parallel sessions. It is not a measurement of a person's time online.
- Period breakdowns by stable user, credential, inbound, node and TCP/UDP protocol.
  A credential can be named for a device, but does not prove a physical device's identity.
- Independent session audits with source, target host:port, resolved IP, selected
  node/selector/rule IDs and names, timestamps, byte totals and end reason.

These are payload counters at the proxy boundary, not NIC/WAN wire bytes. They
exclude transport/encryption overhead. Deltas are assigned to the observed
sample/end bucket; traffic near a UTC boundary can land in the next bucket. A UDP full-cone mapping remains one session;
its audit target is the initial destination, not a log of every subsequent packet
or unsolicited reply destination. HTTP keepalive is one upstream connection, not
one request. Gateway pools separate credentials, inbounds and client sources to
avoid assigning another traffic scope's bytes to the first dial's identity.

Locally intercepted DNS has a separate observation (`@local-dns`), including an
asynchronous UDP response that arrives after a sampling tick. Resolver-internal
queries and probes without client attribution are excluded. Locally answered,
redirected or blocked Gateway requests produce metadata-only `@local-gateway`
events with zero forwarded bytes and no invented upstream session opens.

Anonymous inbound traffic and submitted invalid authentication proofs have no
trusted user and are recorded as **unattributed**. The verifier's failure observer
never accepts the submitted username as an authenticated identity. Protocol
rejections before a proof reaches that verifier (for example a missing HTTP proxy
authentication header) are outside that observer's coverage. Failure-only proof
events identify the authentication protocol (for example HTTP), while established
traffic sessions use TCP/UDP.

No tokens/passwords, request URLs/paths, headers, payloads or request bodies are
stored in traffic audits. Management security events separately include the actual
socket peer IP, route template, method, credential ID and result. User edits record
only login/role/disabled before and after values; forwarding headers confer no
source identity. The existing 1,000-event management-security retention remains.

## Collection and durability

Ordinary forwarding reuses `Counter`'s existing atomics. Successful reads/writes
perform no new recorder lookup, lock, allocation, clock read or SQL operation.
Lifecycle admission/removal attaches a sidecar; a worker samples it once per second
and writes detached SQLite batches approximately every five seconds. It sleeps
when idle. SQL transactions run outside the sampling/lifecycle mutex. Opening and
closing many connections still has an observable memory and persistence cost;
see [measurements](benchmarks/user-usage.md).

Queries flush already sampled deltas, so payload totals may lag by one sampling
interval. Graceful shutdown takes a final sample/flush. An abrupt process exit
can lose observations since the last successful checkpoint (normally up to about
five seconds, potentially longer under scheduling or storage failures). Previously
active persisted audits become `interrupted` at their last checkpoint on restart.

Failed writes retain an immutable batch and retry it before newer observations.
A transaction marker prevents double application of an ambiguously committed batch.
Aggregates are independent of audit retention and the bounded 8,192-checkpoint
pending audit map. On overflow, audit checkpoints can be omitted; totals continue
to accumulate. Health exposes `droppedAudit` since process start, `pendingAudit`,
`lastFlush` and `persistenceError`; the UI shows incomplete coverage. An audit is
therefore operational evidence, not a lossless compliance or billing ledger.
A prolonged database outage can grow aggregate/session backlogs; the audit bound
is not a hard bound on total recorder memory.

## Retention

| Data | Default | Configurable range |
|---|---|---|
| Completed audit age | 30 days | 1–365 days |
| Completed audit count, global | 100,000 | 100–1,000,000 |
| Hourly buckets | 30 days | 1–90 days |
| Daily buckets and minute deduplication | 365 days | hourly retention through 730 days |
| Lifetime totals/peak counts | Retained | Independent of history pruning |

Active audits are exempt from the completed-row cap. The cap is enforced when
completed records are flushed; age maintenance runs on active flushes at most
hourly and when settings change. Old data can remain on disk during a fully idle
runtime until the next maintenance. Shortening retention deletes expired history;
lengthening it cannot reconstruct deleted data. IDs survive user, credential and
node deletion. Runtime statistics are excluded from configuration-only backups.

## API and authorization

Existing authenticated HTTP endpoints, all under `/api/v2/auth`:

| Method and path | Permission | Purpose |
|---|---|---|
| `GET /usage` | `usage:own` | Summary, series, top 200 entries per breakdown |
| `GET /usage/audit` | `usage:own` | Cursor-paged independent sessions |
| `GET /usage/owners` | `usage:read` | Historical owner IDs, up to 200; `after` cursor |
| `GET /usage/settings` | `usage:own` | Effective retention |
| `PUT /usage/settings` | `users:manage` | Save retention and apply cleanup |

Owner defaults to the signed-in user. Selecting another owner or
`owner=unattributed` additionally requires `usage:read`. Proxy-only users have
`usage:own`; read-only operators and administrators can read other owners. Scoped
API tokens must include the needed permissions, still bounded by their owner's
current role. No-management/native runtimes do not expose these routes.

Report filters: `owner`, `credentialId`, `inboundId`, `nodeId`, `protocol`, `from`,
`to`, `interval=hour|day|month`. `from`/`to` are Unix **seconds**, half-open UTC;
report ranges round outward to whole retained hour/day buckets. Summary activity
minutes, live rates and peak concurrency remain whole-user metrics even when a
breakdown dimension is filtered. Breakdown rows describe the selected period.

Audit additionally accepts exact `source`/`target`, `result`, `limit` (1–200,
default 50) and an opaque `before` cursor returned as `next`. Date filters apply
to session **start** and do not round. An active session started before the selected
period will not appear in that audit range, even if it transferred bytes inside it.
The UI uses 50-row pages, admin owner selection, UTC presets/custom dates, trends,
breakdowns and expandable audit details. The owner selector initially loads up to
200 historical IDs; further historical IDs remain accessible using the API.

`firstSeen`, `lastSeen`, audit timestamps, `updatedAt` and `lastFlush` are Unix
**milliseconds**. Series `start`, report `from`/`to` are Unix **seconds**.

Quota, bandwidth limits and admission enforcement are intentionally separate future
work. Enforcement should consume authoritative live accounting rather than query
sampled, potentially delayed historical reports for every packet.

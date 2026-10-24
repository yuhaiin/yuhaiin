# Management security audit

The optional management identity module extends its existing private security
ledger. Migration 11 retains users, credentials, groups, OIDC bindings and audit
IDs, adds indexed metadata, and creates retention settings, a durable forwarding
outbox and delivery counters. A stable random instance ID identifies the ledger
across restarts. Restoring ordinary configuration cannot replace these tables.

Management databases now use SQLite `synchronous=FULL` with the existing journal
selection (WAL locally, DELETE in NFS mode). Successful commits request durable
syncs from SQLite/the filesystem; storage hardware and filesystem behavior still
bound physical durability. Configuration and traffic stores keep their existing
journal configuration. No SQL, export or OIDC operation was added to forwarding.

## Three separate records

* Management changes use a local transactional ledger. User/group, role, token,
  access/resource policy, OIDC and audit-setting mutations insert their audit in
  the same private SQLite transaction. An audit/retention/outbox database write
  error aborts that transaction. Forwarding being unavailable does not reject a
  locally audited management change.
* Connection metadata uses the existing bounded traffic audit pipeline. It can
  drop records under pressure and is not a lossless compliance ledger.
* User traffic/quota reports aggregate traffic and resource counters. They are
  not a substitute for either event history.

The pre-existing cross-store secret isolation guard writes a durable
`configuration.sensitive_change_authorized` intent before a configuration write;
this is not proof that another database's change committed. Similarly,
`secret.retrieval_authorized` and `security.audit_export_authorized` describe
permission to return data, not proof that a browser received it. Failed login
and permission-denial logging is best effort: an unavailable ledger does not
turn a denial into access. Observed local audit failures are counted in memory
until process exit. Atomic changes that fail auditing return an error rather
than silently reporting successful auditing.

## Event contents and API

Records contain actor and resource IDs, timestamp, operation, result, socket
peer, HTTP method and route template, credential **ID**, authentication method,
policy revision where applicable, fixed denial reasons, and safe before/after
metadata. Tokens are identified as `token`; browser sessions identify password,
GitHub, Google or the configured OIDC provider. CLI/offline actions use `local`.
Request bodies, URL queries, forwarded peers, passwords, full credential proofs,
private keys and forwarding secrets are never copied into the ledger. Changes
larger than 16 KiB become a fixed truncation summary with their original size.
Large complete policy snapshots therefore require configuration history, not the
bounded audit diff alone.

All endpoints below are under `/api/v2/auth/events`:

| Method and suffix | Permission | Behavior |
| --- | --- | --- |
| GET `/page` | `security:read` | Structured `AuditPage` |
| GET `/export` | `security:export` | Same bounded page as a JSON attachment; durable authorization required |
| GET `/settings` | `security:read` | Public retention/forwarding configuration |
| PUT `/settings` | `security:write` | Revision-checked update; private fields also require `secrets:manage` |
| GET `/status` | `security:read` | Worker, backlog, delivery/drop/failure counters |

The legacy GET `/events` array remains bounded at 1,000 entries. New APIs return
IDs and counters as exact decimal **strings**, including values above JavaScript's
safe integer range. `AuditPage` contains `instanceId`, `items` and `nextCursor`.

`limit` defaults to 100 and cannot exceed 1,000. Optional `event`, `actorId`,
`subjectId`, `result`, `authMethod` and `reason` are exact filters. `search` matches
literal operation/actor/resource text (SQL wildcard characters are escaped).
`from` and `to` are inclusive Unix seconds. Each text filter is at most 256 bytes.
Opaque cursors pin an upper event ID and a descending position within one ledger;
new events cannot push themselves into a later page. Retention may expire older
entries between requests, so this is not a held database snapshot or a lossless
bulk dump. Export each page with the same filters/cursor and deduplicate by
instance plus event ID. Database rows are read and closed before network output.

## Retention and forwarding

Default local retention is the newest **10,000 actual rows** and at most **90 UTC
days**. Configurable bounds are 1,000–100,000 rows and 0–3,650 days; zero disables
age expiry but not the row bound. Writes and the single background worker prune
expired rows. Reducing retention is immediately destructive after a successful
settings commit, and the UI confirms that action. ID gaps do not shorten the
retained row count.

Forwarding is disabled initially. Enable HTTPS SIEM JSON or syslog over TLS in
Account & Security → security audit → retention and forwarding. One worker owns
a durable 64–16,384 item outbox (default 4,096), with one in-flight attempt and
batches of at most 64 records. Retries back off from 5 seconds to 5 minutes, and
each attempt has a 5-second deadline. Changing settings cancels the current
attempt; an acknowledgement for an old settings revision cannot discard queued
records. The worker stops before closing the private database.

The outbox owns its copy independently of local row-count retention. A full queue
drops the **new delivery copy** and increments a persistent drop counter while the
local event and management change still commit. Age expiry deletes expired queued
copies and increments the same counter. Lowering the queue limit below the
backlog is rejected. Disabled forwarding retains pending copies until age expiry;
changing the destination sends pending copies to the new destination. The
persisted backlog, oldest timestamp, success/failure timestamps, delivered count,
fixed failure class and drop count are visible in the UI/API. These are delivery
health metrics, not guarantees of complete external retention.

Full destination URLs can contain webhook proofs in their path. Both the full
URL and optional HTTPS bearer token are **write-only**. GET returns an empty
`endpoint`, `endpointConfigured`, a scheme/host-only `destination`, and
`tokenConfigured`. Empty writes preserve either private value. `clearEndpoint`
and `clearToken` explicitly remove them. Any provided replacement or clear,
including an equal existing value, requires `secrets:manage`; ordinary security
writers cannot redirect a saved proof. No private URL/path or token appears in
before/after metadata or delivery failures.

HTTPS accepts `https://host/path`, rejects userinfo, query/fragment credentials
and redirects, and verifies certificates with system trust (TLS 1.2 minimum).
Payloads are `{ "instanceId": "...", "events": [AuditRecord, ...] }`, optionally
using `Authorization: Bearer ...`. A 2xx response acknowledges a batch. Remote
bodies are neither stored nor logged. An acknowledgement followed by a local
commit failure may replay a batch: consumers must deduplicate `(instanceId,id)`.
A full or expired outbox can lose deliveries, so this is not exactly-once or an
unbounded at-least-once guarantee.

Syslog accepts `tls://host[:port]` (default 6514), verifies system trust and sends
RFC 5424 messages with RFC 5425 octet counting. Each JSON body has `instanceId`
and `event`; UTF-8 lengths count bytes. No bearer token is supported. Socket-write
success only acknowledges transport, **not collector processing or persistence**.
No UDP or plaintext syslog transport is provided.

Protocol references: [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424.html) and
[RFC 5425](https://www.rfc-editor.org/rfc/rfc5425.html).

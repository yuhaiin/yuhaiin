# Identity resource governance

Resource policies extend Traffic Control and the existing Account & Security
user-usage report. The optional management identity module supplies authenticated
user, credential and group IDs to the networking layer. Core networking does
not import management authentication. Android and local deployments can omit
the module completely.

## Enable and compose policies

In **Traffic Control → Identity resource policies**, configure the default user
policy, group policies, user overrides and credential policies. Validate the
draft and confirm activation. A stale revision returns HTTP 409 and keeps the
editor draft. Readers require `resources:read`; activation requires
`resources:write`. Existing scoped API tokens gain neither permission
automatically. Resource policy saves and their management audit metadata commit
in one private management-database transaction before runtime publication.

Authenticated forwarding applies all relevant scopes:

1. Existing global, inbound and route-rule Traffic Control buckets.
2. The default user profile, or that user's explicit override.
3. Every member group's individual profile, composed into the user's bucket.
4. Every member group's shared aggregate bucket.
5. The credential's individual bucket.

Zero means unlimited. Individual profiles compose by the smallest nonzero rate
and normalized burst in each direction. Admission limits compose by the
smallest nonzero cap/rate/burst. Group IDs sort before compilation; membership
or map iteration order cannot change the result. An explicit user override
replaces only the default user policy. It cannot remove group or credential
constraints. A shared group bucket is shared across its members and devices;
an individual group profile is applied separately to each member. A credential
budget is shared across that credential's connections, rather than destinations.

Policies update established stream handles and subsequent UDP datagrams without
restarting listeners. Surviving buckets preserve earned credit and active
session counts. Lowering a session cap blocks new admissions while existing
leases drain. Updates and temporary policy removal do not refill CPS buckets.
Unknown authenticated IDs fail closed when resource policies are enabled.

Resource policies do not authenticate anonymous/shared-password traffic. Such
traffic retains existing global/inbound/route controls and has no user budget.
For protected enterprise entry points, use inbound authentication mode `users`
and a managed Traffic Access scope. `mixed` explicitly permits a legacy path;
the UI warns about it. Access authorization and resource admission remain
separate decisions.

## Sessions and packets

User and credential governors enforce total, TCP and UDP active-session caps,
connection creation rate, and optional PPS. Protocol caps are checked before
the shared TCP/UDP creation budget. Credential admission precedes user admission,
and identity admission precedes shared ingress admission. Repeated failures
against a user's own limits cannot spend other users' global creation tokens.
Session release is idempotent across setup failure, normal close, cancellation,
listener shutdown and identity revocation. UDP sessions remain source/migration
keyed full-cone associations with one shared outbound socket; destinations do
not create independent resource budgets.

Forwarding uses precompiled immutable selections and shared live counters. It
performs no membership SQL or historical usage query per packet. Rate buckets
lock only selected scopes. With an unlimited global profile, unrelated users
do not contend on a global rate mutex. A limited shared group deliberately
serializes its own aggregate reservations.

## Byte quotas and UTC resets

Configure up to one quota of each period per user, group or credential:

| Period | Window |
| --- | --- |
| Daily | 00:00 UTC through the next 00:00 UTC |
| Monthly | First day at 00:00 UTC through the next month's first day |
| Lifetime | Stable quota ID, no automatic reset |

Byte values are exact decimal strings up to signed 64-bit maximum; the editor
does not convert them through JavaScript `Number`. Upload, download and combined
budgets apply simultaneously. All applicable scopes reserve atomically in a
fixed lock order. TCP can receive a partial grant; UDP must fit as a whole.
Accepted bytes settle the reservation, and failed/short writes refund unused
bytes across every selected scope. Concurrent reservations cannot exceed a
running process's hard cap. A stream holds at most one 16 KiB quota reservation
while pacing or writing. Idle reads reserve no bytes.

These are application bytes accepted at the client-facing admission boundary,
including framing present there, excluding network encapsulation and
retransmission. Upload can be admitted before a later outbound failure. They
can therefore differ from sampled outbound UserUsage reports and wire counters.
Already admitted work completing after midnight belongs to its reservation's
window. Old window handles refuse new bytes at the boundary; the module
publishes fresh windows on its one-second maintenance tick. Failed publication
keeps expired handles closed to new admissions.

| Action | Exhausted behavior |
| --- | --- |
| Block new | Reject new sessions; backpressure existing TCP and drop UDP until reset or a policy change permits traffic |
| Terminate | Reject new sessions, stop forwarding and interrupt affected active session I/O; transport owners perform normal cleanup |
| Throttle | Permit further bytes through the existing limiter at the reduced speed |
| Warn | Permit further bytes and emit configured threshold alerts |

Throttle and warn are not hard byte caps. Group quota throttling uses a shared
group reduced-speed bucket. Quota exhaustion does not revoke the underlying
proxy credential. Termination signals trigger a targeted session sweep; a
one-second sweep also covers policy changes and recovered exhaustion. It does
not wait for slow graceful transport shutdown or close unrelated users.

Changing a quota's period requires a new quota ID, including after removing and
re-adding a definition. Reusing the same ID preserves usage. New IDs deliberately
start a new budget and should be treated as a security-sensitive policy edit.

## Persistence and recovery

Migration **10, `resource_governance`**, adds private resource configuration,
normalized group references, immutable quota definitions, quota windows and
threshold history. A referenced group cannot be deleted until its resource
assignment is removed. IDs and historical credential ownership survive account
metadata deletion. Ordinary configuration restore does not replace this private
database or reset quota usage. Back up management identity state separately.

The quota ledger has one background writer and persists credit **before** it
can be forwarded. It grants at most **4 MiB** of unconfirmed credit per selected
scope/window/dimension. Requests and outstanding writes are bounded to 256;
failure retries use the same idempotent monotonic counters. TCP waits with
deadline/cancellation support; UDP drops when durable credit is unavailable.
No synchronous SQLite write occurs in packet reservation or settlement.

Dirty measured counters checkpoint once per second, in batches of at most 256.
On abrupt recovery, durable charged bytes beyond measured bytes become a
conservative recovery charge. The discrepancy from the last durable measured
checkpoint is at most one 4 MiB grant per dimension/window, including in-flight
reservations, plus any prior recovery charge. Upload, download and combined
recovery bounds are independent and need not add up. A clean shutdown after
settling writes durably returns unused credit; outstanding writes retain their
conservative bounds. Tests cover lost commit acknowledgements, failed storage,
clean restart and simulated process loss. This is not billing-grade wire
accounting or a multi-instance shared quota service. Only one live ledger may
write a management database.

Old quota plans retire before unused credit is reclaimed. Memory eviction waits
for reservations and pending persistence to settle, so reactivation cannot
create a second live balance. Expired windows and removed definitions are
reclaimed by maintenance. Durable window/definition records remain to prevent
usage resets when old IDs are reused; they are not a second traffic analytics
pipeline. Governors remain until outstanding leases and creation-rate debt have
drained. At capacity, new identities/state are rejected rather than evicting
live budgets.

## Reports, alerts and bounds

The existing user-usage page adds current quotas, measured/recovery bytes,
remaining budget, UTC reset, enforced scope speeds, active sessions/caps,
CPS/PPS, rejection counts and the most recent rejection reason. Per-scope rates
show simultaneous constraints; they do not predict the throughput a remote
connection will achieve. Owners require `usage:own`; viewing another owner's
report or alerts additionally requires `usage:read`. A current group member can
see its aggregate group quota. Former members lose that visibility; historical
credential alerts retain their immutable owner ID.

Threshold percentages are deduplicated per window, including reorder/reload.
Activation evaluates recovered counters and newly configured thresholds without
requiring another packet. The live event queue and persistence retry batch each
hold at most 1,024 alerts. Local history retains the most recent **10,000** rows.
Cursor IDs remain decimal strings. Storage failure retains the retry batch;
overflow drops events with an observable counter. This bounded operational
history is not a lossless compliance ledger.

Status includes pending writes/alerts, persistence failures, refresh failures,
denials and dropped alerts. The usage warning indicates failures observed since
startup; it is not a claim that storage is currently unavailable. Limits are
65,536 authenticated credentials, 64 memberships per user, 1,024 configured
groups, 8,192 user/credential overrides combined and 262,144 live quota windows.

Endpoints under `/api/v2/auth`:

- `GET/PUT /resources`, `POST /resources/validate`, `GET /resources/status`.
- `GET /usage/resources?owner=...` and `/usage/resource-alerts?owner=...&before=...`.

See [resource measurements](benchmarks/resources.md) for reproducible local
benchmarks and their limits, and [Traffic Control](traffic-control/README.md)
for existing ingress/route shaping and lightweight scheduling behavior.

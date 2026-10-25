# Intelligent outbound selectors

Selectors keep their stable IDs and existing `nodeId`. Without an explicit
`policy`, selection remains manual. Existing deployments do not start periodic
probes or speed tests after this migration. The browser configures policy and
reads status; decisions are made by the backend while the browser is closed.

The selection engine extends existing node observations and persistence. The
monitoring follow-up adds shared scheduled probes, optional periodic download
tests, global defaults and selector overrides. Closed/Open/Half-open admission
adds bounded recovery trials and generation-safe evidence. Prometheus additions
and traffic-control qualification remain subsequent reliability work.

## Configure and observe

Open **Outbound → Selectors**. Keep the selected node for manual mode, manual
lock, and the optional explicit selected-node fallback. Add candidate Node IDs,
enable them, and configure priorities (lower first) and nonnegative connection
weights. Candidate IDs are protected from deletion, including subscription
refresh. Referenced disabled nodes cannot receive traffic.

| Mode | New connections |
| --- | --- |
| `manual` | Existing selected `nodeId` |
| `failover` | Lowest priority healthy candidate; optionally prefer a configured node |
| `lowest_latency` | Lowest fresh, comparable RTT EWMA |
| `highest_throughput` | Highest fresh active download measurement |
| `balanced` | Highest normalized, weighted score |
| `weighted` | Random tickets proportional to weights among eligible candidates |

Set `locked: true` to temporarily use `nodeId` while retaining the automatic
policy. Unlock to resume it. `failover` is sticky by default after recovery;
`returnToPreferred` permits returning to the best priority/preferred node.
Other metric modes re-rank only after their improvement/hold rules permit it.
Weighted mode distributes new connection/session creations and has no single
fixed winner. Status shows the first eligible priority candidate as its
representative; connection metadata contains the actual chosen node.

TCP and UDP have independent evidence and decisions. Opening a PacketConn alone
does not create UDP remote-success evidence. A received datagram records one
reply observation per session. TCP connect observations indicate the outbound
Conn call succeeded; lazy protocols may not yet have completed a remote tunnel
handshake. Optional native protocol status remains separate. No protocol-native
state is inferred from constructing a proxy.

Use **Probe now** separately for TCP and UDP, then **Measure download** when a
speed-based policy needs it. TCP tests retain existing per-node latency-target
and explicit insecure-setting overrides, but only verified HTTPS observations
with the selector's exact target qualify as comparable HTTPS RTT. Automatic
selectors use verified HEAD responses consistently: legacy GET probes remain
visible as `https_get` evidence but do not enter that HEAD ranking cohort. UDP RTT uses
DNS response tests with an exact `host:port/domain` target. A different target,
transport, expired result, or zero/unknown RTT is never ranked as a fast sample.
The existing Nodes page and manual latency tools remain available.

The live panel exposes raw RTT, valid sample count, active-test Mbps, recent
failure ratio, active connection load, normalized components, selection reason,
and up to 64 recent switch events per selector. Events and switch counters are
runtime-only in this delivery. Per-node observations and active measurement
summaries use the existing `node_runtime_stats` persistence, with its normal
five-second/crash-loss window. Ranking snapshots refresh once per second and
immediately on configuration activation. A read-only status request never dials.

## Measurements and eligibility

Policy numeric zero values select defaults, except where zero has a natural
meaning (weights, minimum throughput, priority). Important defaults:

| Setting | Default |
| --- | --- |
| Minimum valid RTT/speed samples | 3 |
| Measurement lifetime | 120,000 ms |
| Maximum comparable RTT | 5,000 ms |
| Maximum recent failure ratio | 0.5 |
| Consecutive failures / recovery observations | 3 / 2 |
| Absolute / relative RTT improvement | 10 ms / 10% |
| Minimum score improvement | 0.05 |
| Minimum hold / switch cooldown | 30,000 / 15,000 ms |

RTT EWMA uses `0.8 × previous + 0.2 × sample` in timestamp insertion order.
Jitter is the same smoothing of absolute deviation from the prior RTT EWMA.
The last 64 remote observations determine the recent failure ratio. Separately
retained 64 latency samples prevent business-connection churn from evicting
manual probe measurements. Only fresh observations qualify. Recovery requires
the configured consecutive successful observations while recent failures remain.
Unknown states have no recent remote evidence. Disabled candidates never qualify.

Eligibility is evaluated before ranking. RTT modes require the minimum number
of comparable valid samples. Throughput modes require successful, fresh active
measurements for the exact configured `speedTarget`; passive business upload or
download Bps never implies capacity. An upload weight/minimum requires an upload
measurement; this delivery provides download tests only, so leave upload weights
and minimums at zero. Jitter is a timing estimate, not packet-loss measurement.

Balanced components are bounded in `[0,1]`:

- RTT and jitter: `reference / (reference + measured milliseconds)`.
- Download/upload: `measured Mbps / (reference Mbps + measured Mbps)`.
- Stability: `1 - recent failure ratio`.
- Connection load: `reference / (reference + active TCP + active UDP)`.

Score is the weighted sum divided by the sum of weights. All-zero weights select
RTT/download/stability weights `0.5/0.3/0.2`. Default references are 100 ms,
100 download Mbps, 30 upload Mbps, and 100 active connections. These are tuning
scales, not guaranteed link capacities. Set download/upload weights to zero for
a latency/stability-only profile without active speed measurements.

An eligible current node remains selected during minimum hold/cooldown. An RTT
switch must meet **both** absolute and relative improvement thresholds. A failed
or otherwise ineligible current node bypasses these suppression rules, allowing
new connections to move. Live status explains suppression as well as switches.

When no candidate qualifies, `fallback` is explicit:

- `reject` (default): fail new connections with an explanatory error.
- `selected`: use configured `nodeId` only if that node and candidate are enabled;
  this intentionally overrides health/ranking requirements.
- `priority_unknown`: allow unknown candidates by priority, with no implied
  health or measured-capacity guarantee.

No fallback implicitly chooses Direct. Existing L4 routing and Gateway admission
remain authoritative. Selection does not retry application requests. Existing
TCP streams and UDP sessions keep their outbound; policy changes do not migrate
an established NAT session or replay a non-idempotent request.

## Bounded manual download tests

`node.speed` requires the existing `nodes:write` management permission and an
explicit HTTPS URL. It traverses the selected candidate's actual proxy. TLS is
verified; there is no insecure switch. Redirects are rejected. Compression is
rejected and the client requests identity encoding. `Range: bytes=0-N` is used;
HTTP 200 servers without Range and valid HTTP 206 responses are supported.
The response streams to a discard sink with a bounded buffer. Connection/headers
are outside the payload timing window; byte count includes only consumed payload.

| Limit | Default | Hard maximum |
| --- | --- | --- |
| Download bytes per test | 4 MiB | 64 MiB |
| Payload duration | 5 seconds | 15 seconds |
| Request timeout | 10 seconds | 30 seconds |
| Instance-wide UTC daily reservation | 64 MiB | 1 GiB |
| Concurrent tests | 2 | 2 |

The administrator may use a smaller daily limit per request. All tests share the
instance's durable UTC-day reservation; budgets are not independently multiplied
by selector/node/browser count. The full byte allowance is reserved before any
network traffic. Cancellation/failure consumes the reservation. Configuration-only
export/restore does not reset it. Reaching byte/time limits is normal success,
provided at least 1 KiB was measured; failures do not invent a Mbps value.
Repeated successful tests against the same target within two minutes smooth Mbps
with the same 0.2 factor and increment sample count (maximum 64). A failed or new
target test resets this chain. Values approximate this target at this moment.
They are not Internet capacity guarantees. The outer node wrapper still counts
these bytes as actual transferred traffic.

Periodic monitoring is disabled by default on all platforms. See the scheduler
section below for explicit enablement and mobile/metered-network controls. Probe/speed targets are privileged administrator-chosen
resources; do not delegate `nodes:write` to untrusted accounts. URL user-info and
fragments are rejected for speed tests. URLs are never Prometheus label values.

## Runtime and persistence

Migration 18 adds nullable-JSON `policy_json` to `outbound_selectors`, defaulting
to JSON null, and `node_speed_budget` for a singleton UTC-day reservation.
The selected-node foreign key and optimistic `revision` checks remain in place.
Older configuration JSON exports with the exact four-column selector table are
upgraded to a null policy during validation/restore; arbitrary schema changes
remain rejected. Runtime observations are omitted from configuration exports.

Runtime snapshots cache candidate configurations and precompute rankings and
weighted cumulative tickets. New connection selection does no SQLite lookup,
network probe, sorting, or scoring. Weighted choice is O(log n); deterministic
ranking is O(n), using priority and Node ID as tie breakers. One shared worker
refreshes snapshots; there is no resident goroutine/timer per candidate.
Set, point-as-endpoint, and nested network-split dependencies are checked for
cycles on node save/subscription replacement. Node dependencies may not exceed
64 levels. Selectors reference Nodes only, not other Selector IDs.

## Validation and performance

Tests use local TLS listeners and fixed evaluation timestamps. They cover modes,
expiry, unknown speed, mismatched targets, hysteresis, recovery, disabled nodes,
weights, policy references/cycles, reserved SQLite connection availability,
1,000 concurrent snapshot readers, request pinning, TLS rejection, Range,
compression/redirect rejection, time/byte truncation, and durable daily budgets.

Run:

```sh
go test -race ./pkg/node ./pkg/store ./pkg/net/latency ./pkg/httpapi ./pkg/storage/sqlite
go test ./pkg/node -run '^$' -bench BenchmarkSelector -benchmem -benchtime=300ms -count=2
```

See [measured results](benchmarks/data/selector-2026-10-25/ranking-and-target.txt).
These are Go selection microbenchmarks, not real-link throughput or TCP/VPN
handshake measurements. On the recorded Ryzen 5 5600G run, ranking 1,000
candidates took roughly 0.1–0.14 ms depending on strategy. Target resolution
took 429–434 ns in manual mode, 432–436 ns in failover, and 456–457 ns
with weighted tickets; all had six allocations (632 bytes). The remaining connection allocations belong to existing runtime
proxy/context preparation, not database queries or scoring.


## Shared monitoring schedules

Open **Outbound → Selectors → Monitoring defaults**. Global configuration is
persisted in migration 19's `node_monitoring_settings` table. Existing and older
configuration exports remain importable; pre-v19 exports restore disabled
monitoring defaults. A selector's nullable `probe` and `periodicSpeed` overrides
inherit the global schedules. Creating an override starts with it disabled;
explicitly enable the schedule and Save to authorize periodic traffic.

`node.monitoring.get` is protected by `nodes:read`. Configuration and runtime
network-state changes require `nodes:write`; ordinary browser queries never
start a task. The UI shows task/worker counts, failures, skips and current host
network state. Speed history expands lazily and reads existing per-node status;
up to 16 raw measurements are retained in the existing stats JSON. EWMA capacity
and the raw measurement history are distinct.

The scheduler uses one priority-queue timer and lazily creates a fixed worker
pool, bounded by global concurrency (default four, maximum sixteen). Selector
concurrency can reduce a group limit, never exceed the instance cap. Probe and
speed traffic have separate group limits. Idle instances have no probe workers.
Identical node/transport/target tasks across selectors share one job, using the
shortest requested interval. Initial jobs spread over up to five seconds;
subsequent intervals have configurable jitter (0–0.5). There is no per-node
resident goroutine or timer. Changed/deleted tasks are synchronously canceled;
old canceled probes do not publish replacement samples.

Default interval is 60 seconds, timeout five seconds, failure/recovery thresholds
3/2, and recovery cooldown 30 seconds. Interval is at least five seconds; probe
timeout is 100 ms–30 seconds. Consecutive failed scheduled attempts reaching the
threshold increase that task's interval to at least its recovery cooldown.
This controls recovery traffic; it does not admit Half-open user requests.

Supported tasks are TCP channel creation, verified complete HTTPS HEAD response,
DNS reply over UDP, optional UDP STUN, and an existing protocol-native cached
status provider when implemented. These evidence kinds are distinct. Native
status is used only with a recent timestamp and an explicit connected/healthy/
ready or disconnected/failed/unhealthy state; unsupported status is skipped.
Neither a proxy constructor nor PacketConn creation proves a remote handshake.
No native provider is invented for a protocol that lacks one.

Probes call the candidate Node directly, including its actual protocol chain,
never an automatic Selector or the system's default Direct route. Fixed Node
references and existing dependency-cycle validation prevent Selector recursion.
The native protocol integration remains the source of tunnel-handshake truth.
HTTP/DNS/DoQ/STUN manual probes now propagate cancellation to actual transports.
Scheduled HTTPS never inherits insecure TLS bypass from a manual Node override.
A TCP-connect probe is not counted as a comparable HTTPS/DNS RTT sample.

The shared probe traffic limiter defaults to 65,536 logical bytes per second.
Each task reserves a conservative 64 KiB allowance *before* RTT timing starts;
aggregate connection/datagram reads/writes within that probe cannot consume
more. Budget waits/skips do not mark the node failed or inflate measured RTT.
A lower selector bandwidth override adds a shared lower-rate group limit. This
conservative reservation may reduce achievable probe frequency for large node
sets; raise the explicit global budget or increase interval accordingly. It
bounds logical probe traffic; VPN framing and kernel buffering are not a wire-
rate guarantee. Existing traffic-control integration still needs qualification.

Periodic download tests reuse the verified streaming implementation, two-test
hard cap, and durable daily reservations. They default to once per hour and
at most one concurrent scheduled test; minimum interval is five minutes. Busy
or daily-budget-exhausted tests are skipped without network fallback or an
unlimited retry loop. They never reset a daily reservation by rescheduling.

Network offline transitions cancel tasks. The existing interface-monitor callback
coalesces to the latest interface state, cancels old-network work, and spreads
replacement work when a route/interface returns. Overdue tasks after sleep
execute once and reschedule from completion, without replaying missed intervals.
Android always additionally requires `allowMobile` and a native-host foreground
signal. The new `App.SetMonitoringNetworkState(online,metered,foreground)` binding
lets the Android host report lifecycle/cost transitions. The browser is not the
source of mobile foreground truth. Metered probes are skipped unless explicitly
allowed by the network-cost policy; speed tests require their own `allowMetered`.

`cached_only` never constructs an unused outbound. Other policies may construct
ordinary lightweight proxy clients, but periodic jobs never initiate a new
enterprise VPN login, even on unmetered links: they can reuse a client established
manually. This avoids background MFA/authentication and uncancellable legacy
constructors. Administrators must establish such a candidate once through the
existing manual path before periodic validation can reuse it.

Scheduler tests use Go's simulated-clock concurrency bubbles to cover 1,000
jobs, the sixteen-worker hard limit, cancellation/replacement, deduplication,
independent group limits, deadlines and failure cooldowns without live Internet.
Local listeners verify actual candidate transport and evidence separation.

[Scheduler reconfiguration measurements](benchmarks/data/selector-2026-10-25/probe-scheduler.txt)
showed roughly 13–14 microseconds for 100 unchanged jobs and 135–140 microseconds
for 1,000 jobs, with five owned goroutines (four workers and one coordinator)
in both cases. This is queue reconfiguration cost, outside the forwarding path.
Global monitoring saves use an optimistic revision and reject stale updates.

## Circuit admission and protocol evidence

Automatic, unlocked selectors now use a Closed/Open/Half-open breaker per Node,
transport and threshold configuration. Selectors with the same thresholds share
the breaker and the existing node health window. Manual selectors and manual
locks keep their original behavior. `policy.circuit.disabled` explicitly disables
breaker admission; ordinary eligibility/failure filtering remains in place.

The existing `failureThreshold`, `recoveryThreshold`, `minSamples`, `maxAgeMs`
and `maxFailureRate` govern consecutive failures, minimum recovery successes and
fresh-window failure rate. `policy.circuit` adds:

| Field | Default | Allowed values |
| --- | --- | --- |
| `cooldownMs` | effective probe cooldown (30,000 ms by default) | 1,000–86,400,000 ms |
| `halfOpenConcurrency` | 1 | 1–16 |
| `halfOpenMaxRequests` | max(4, 2 × recovery threshold) | recovery threshold–256 |
| `trialTimeoutMs` | 30,000 ms | 100–120,000 ms |

A threshold crossing immediately blocks new admissions, including callers that
cached the automatic Selector proxy. After cooldown a bounded recovery window
admits trial requests. Failed recovery opens a new cooldown. Successful recovery
closes the breaker; expiration or exhausted request quota cannot create unlimited
retries. Caller cancellation releases a concurrency slot but still consumes its
issued quota. Closed admission requires no trial context, timer or goroutine.

The recovery window also bounds trial TCP dial/Ping operations and UDP session
creation. An established UDP session keeps the original caller context and
outbound Node; receiving a reply releases the trial lease without cancelling
that session. PacketConn creation and successful sends do not prove remote UDP
reachability. Even a zero-byte received datagram is a real reply. There is no
per-packet ranking or session migration for balancing.

Connect success, a TCP response, UDP reply, verified HTTPS, DNS/STUN reply and
protocol-native handshake are distinct evidence labels in candidate details.
Receiving TCP response bytes strengthens its connect evidence; it is not counted
a second time toward recovery. Neither a constructor nor an unsupported protocol
status is reported as a native handshake. Native status providers and actual
remote tests remain the source of stronger evidence for lazy VPN protocols.
Construction failures have a distinct kind and can make that candidate unavailable.

Only explicit network/transport errors condemn a channel. Caller cancellation,
EOF/normal close, application read deadlines, access-policy blocking, quota or
other ordinary application errors, HTTP 4xx responses, and zero-code QUIC stream,
application or transport shutdowns do not open a breaker. Dial timeouts and
network refusals do. Ambiguous protocol application errors remain visible in
protocol diagnostics; they are not guessed to be a network outage.

Admission may choose a pre-ranked alternative when the original circuit is open
or has no trial permit. Once a transport call starts, its error is returned to
the caller; that attempt is never replayed on another Node. Established TCP
streams and UDP sessions retain their original runtime reference. A subsequent
new connection can use another candidate. Existing Set retry semantics remain
unchanged; this feature adds no HTTP request replay.

Transport or referenced-credential changes invalidate health/capacity evidence
and increment a runtime generation. Old plans, probes, speed tests and connection
responses cannot repopulate new-generation evidence. Generation checks also
protect a deleted/recreated Node ID. Renaming/grouping alone preserves the VPN
client and measurements. Active connections can continue carrying traffic using
the old reference, although a protocol's own Close implementation may disconnect
its client when that transport is explicitly replaced.

Node/default selection reads the immutable configuration snapshot instead of
querying SQLite for every new connection. Real upstream credential resolution
uses an immutable secret snapshot populated at identity startup and successful
mutations, refreshed before notifying the node runtime. Missing/failed refreshes
fail closed. Credential listing still exposes metadata only, and runtime Close
removes the secret snapshot. Custom credential Resolver implementations retain
their existing revision-based refresh contract.

The frontend exposes the breaker toggle, cooldown, trial concurrency/quota and
window together with current state, bounded admission counts and recovery reason.
These additions use the existing selector-policy JSON and node-observation JSON;
no additional migration beyond schema 19 is required.

Qualification includes deterministic virtual-clock failure/recovery, rate and
consecutive thresholds, cancellation, deadlines, quotas, epoch changes, no replay,
UDP reply-only recovery, and 1,024 simultaneous connection creators during policy
and health updates. Connection benchmarks include the complete observed TCP/UDP
creation path with a deterministic transport, plus actual loopback TCP sockets.
These isolate overhead and do not measure real VPN throughput.

The 2026-10-25 Ryzen 5 5600G Linux/amd64 run includes GetTarget and complete
observed connection creation on every operation. Three-run medians are below.
The transport is deterministic/in-memory; these measure routing overhead rather
than physical network latency.

| Mode | TCP ns/op | UDP ns/op | TCP bytes/allocs | UDP bytes/allocs |
| --- | ---: | ---: | ---: | ---: |
| manual | 698.5 | 444.9 | 272 / 5 | 288 / 6 |
| failover | 865.5 | 548.2 | 328 / 8 | 344 / 9 |
| weighted | 909.0 | 587.3 | 328 / 8 | 344 / 9 |

[Raw new-flow and cached-proxy results](benchmarks/data/selector-2026-10-25/circuit-new-flow.txt)
and [ranking/target/loopback results](benchmarks/data/selector-2026-10-25/circuit-ranking-and-loopback.txt)
include allocations and repeated samples. Loopback TCP varied from roughly
73 microseconds to 1.1 milliseconds across repetitions; kernel scheduling and
socket churn dominate that run, so it is not evidence of a stable mode-to-mode
network performance difference. No physical VPN speed claim is inferred.

```sh
go test ./pkg/node -run '^$' -bench 'BenchmarkSelector(NewFlow|ConnectionCreation)$' -benchmem -benchtime=500ms -count=3
go test ./pkg/node -run '^$' -bench 'BenchmarkSelector(Ranking|Target|LoopbackConnection)$' -benchmem -benchtime=500ms -count=3
```

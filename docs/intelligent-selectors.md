# Intelligent outbound selectors

Selectors keep their stable IDs and existing `nodeId`. Without an explicit
`policy`, selection remains manual. Existing deployments do not start periodic
probes or speed tests after this migration. The browser configures policy and
reads status; decisions are made by the backend while the browser is closed.

The selection engine extends existing node observations and persistence. The
monitoring follow-up adds shared scheduled probes, optional periodic download
tests, global defaults and selector overrides. Closed/Open/Half-open admission
adds bounded recovery trials and generation-safe evidence. Prometheus metrics and traffic-control qualification extend the same runtime;
remaining completion items are tracked in the enterprise reliability audit.

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
policy. Unlock to resume it. The optional preferred node is a candidate, not a
replacement for health/capability checks. Click **Preferred** again to clear it.

- `failover`: initial selection uses the healthy preferred node when configured,
  otherwise priority. After failover it keeps an eligible survivor by default;
  `returnToPreferred` allows returning by preferred/priority order once hold and
  cooldown permit it.
- `lowest_latency`, `highest_throughput`, `balanced`: with a preferred node set,
  disabling return keeps an eligible non-preferred survivor and continues ranking
  other non-preferred alternatives. Enabling return only admits the preferred
  node when it wins the metric and clears the same improvement/hold/cooldown
  rules. A slower preferred node never overrides the metric. Without a preferred
  node, these modes keep their ordinary ranking behavior.
- Initial selection and loss of the current candidate's eligibility permit the
  preferred node regardless of return suppression; the setting cannot pin an
  unhealthy, disabled, stale or unusable survivor. TCP and UDP apply it to their
  own evidence independently. The precompiled admission order may also use the
  preferred node if the current candidate cannot admit a circuit recovery trial;
  no transport request has started at that point and nothing is replayed.
- `weighted`: distributes new connection/session creations by weight and has no
  single fixed winner. Preference/return controls do not apply and are hidden.
  Status shows the first eligible priority candidate as its representative;
  connection metadata contains the actual chosen node.

Status reports `preferred_return_disabled` when that policy selects an
alternative to the best preferred metric. Retained choices count in the bounded
suppression metrics alongside hysteresis/hold/sticky-failover reasons. Candidate
health and raw metrics remain visible; suppressing return does not mark the
preferred candidate unhealthy. The existing policy JSON stores these settings,
with no new migration. Existing manual configurations remain unchanged.

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
download Bps never implies capacity. Upload weights/minimums independently require
fresh, successful upload measurements for `uploadTarget`. A new upload never
refreshes download validity or its EWMA; legacy measurements with no direction
are download-only. Upload-only balanced profiles do not require a download sample.
Jitter is a timing estimate, not packet-loss measurement.

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

### Explicit upload measurements

`node.speed` accepts `direction: "upload"` only with `allowUpload: true` and an
administrator-configured HTTPS endpoint implementing the following protocol.
The legacy omitted direction remains download. Upload tests use the same node,
policy-bound proxy, admission slots, durable UTC reservation and transport-byte
limiter as downloads. Neither selector creation nor editing upload weights starts
a test. Periodic upload tests are independently disabled by default; configure
optional `MonitoringConfig.uploadSpeed` or `SelectorPolicy.periodicUpload`.
The same mobile/foreground, metered-network and established-VPN checks apply.
Clone restoration disables all three global schedules and every enabled
Selector schedule override; original-instance recovery preserves them.
Both directions share the two-test hard limit and one durable daily spend.

Upload protocol version 1:

1. Send HEAD to the exact configured URL with `Yuhaiin-Upload-Test: 1`.
   Require HTTP 200/204 and the same response header before sending any payload.
2. Send one non-rewindable POST to that URL, using uncompressed
   `application/octet-stream`, identity response encoding and no cache.
   Generate random bytes in bounded buffers until the byte/duration budget is
   reached. Do not follow redirects or retry/replay the POST.
3. Require HTTP 200, the same protocol header and an uncompressed JSON response
   of at most 4 KiB: `{"version":1,"receivedBytes":8192}`. Reject duplicate or
   unknown members, wrong version/count, early acknowledgement, partial body,
   business errors, transport failures or fewer than 1 KiB of acknowledged data.

Download and upload retain the same 4 MiB default/64 MiB maximum payload budget,
5-second default/15-second maximum payload-generation window and 30-second hard
whole-request timeout. In-flight delivery and acknowledgement must finish within
the configured whole-request timeout. Upload Mbps uses acknowledged bytes from
first body read through the complete acknowledgement, including final delivery
and acknowledgement latency. HEAD/TLS setup is outside that window. This is a
target/time-specific approximation and can underestimate path capacity.

Selector `uploadTarget` and `uploadTest` control the saved target, explicit consent
and limits independently of `speedTarget`/`speedTest`. A periodic override uses
these saved test settings when present. Global settings and disabled overrides
are inherited using the same rules as download scheduling. Manual requests do
not turn on a periodic schedule. A wrong direction in either schedule slot is
rejected. Failed/cancelled attempts still consume their reservation.

Latest download (`throughput`) and upload (`uploadThroughput`) keep independent
time, target, successful-sample count and EWMA in existing node statistics JSON.
The existing 16-entry raw history includes both directions. Config generation
changes invalidate both rankings. Repeated tests against the same target within
two minutes accumulate samples independently. For infrequent periodic tests,
choose a minimum sample count of one and a suitable measurement validity window,
or perform multiple manual tests within that smoothing window; a lone hourly
sample does not satisfy the default three-sample threshold. The UI shows each
direction's fresh sample time/count and labels historical Mbps by direction.

A separate endpoint tool is available without opening an app listener:

```sh
go run ./cmd/speed-test-server \
  -listen 127.0.0.1:8443 \
  -certificate-file /private/measurement-chain.pem \
  -key-file /private/measurement-key.pem \
  -enable-upload
```

Use `/download` and `/upload` on its configured HTTPS address. Certificates must
be trusted by the measuring instance. Select an explicit reachable bind address
and control access to the service when deploying it for remote candidates. The
tool defaults to loopback, requires certificate/key files, rejects plaintext
fallback and leaves uploads off without the flag. It streams at most 64 MiB,
bounds read/write lifetimes and allows at most two active requests. It is not an
ACME manager, generic file upload service or an extra management endpoint.

No new SQLite migration is needed: policy/monitoring/observation JSON is extended;
the existing UTC budget row is shared unchanged. New finite metrics include
`yuhaiin_outbound_upload_tests_total{outcome}`, `active_upload_mbps`,
`last_upload_success`, `last_upload_timestamp_seconds` and
`last_measured_upload_mbps` under the same `yuhaiin_outbound_` prefix. Existing
download metrics retain their meaning and never receive upload samples.

Hermetic coverage includes `TestUploadRuntimeLocalTLS` (actual verified HTTPS,
NodeRuntime, persisted samples after restart and upload-oriented selection),
`TestUploadAndDownloadShareDurableDailyBudget`, independent stale/unknown/invalid
sample tests, schedule deduplication/cost controls, and transport/server protocol
failure tests. The TLS fixture scopes a custom trust root to a child process,
without changing production verification. A cancelled or redirected POST is not
replayed. Frontend tests and three-width synthetic browser interactions are
separate from these real backend tests.

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
Node/transport/target tasks across selectors share one job only when their
execution settings match; the shared job uses the shortest requested interval.
Different timeouts, bandwidth, network cost, concurrency, failure threshold,
cooldown or jitter produce separate jobs. These jobs still obey the global
worker and bandwidth limits, but can produce additional probe traffic; their
results contribute to the same existing node observation history. Initial jobs
spread over up to five seconds;
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

The currently exposed native providers are:

| Provider | Cached native evidence | Deliberate limit |
| --- | --- | --- |
| OpenVPN | Existing native session error/auth/closed state; initialized session without error reports connected. | Does not start a login or test arbitrary destinations. |
| GlobalProtect | Existing gateway session, authentication, idle-disconnect and reconnect state. | Idle demand-driven sessions are not reported as a new handshake. |
| L2TP | Existing native session/auth/closed state. | Static mode reports configured, which cannot establish native health. |
| SoftEther | Existing session and running/receive-loop state. | Connected is cached tunnel-session evidence, not a fresh remote application reply. |
| Tailnet | Existing in-memory backend/control state and assigned addresses. | Configured/control readiness is not a peer WireGuard handshake and does not create native success samples. |

These reads use an already cached proxy exposing `NodeRuntimeStatusProvider`.
Other protocols, or wrapping chains that do not expose that interface, are not
assigned native handshake evidence. They can still use real end-to-end TCP,
HTTPS, DNS or STUN observations through the complete candidate chain. No
provider lookup issues a Tailnet status RPC, starts a protocol client or claims
that a healthy native control plane proves every data destination reachable.

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
rate guarantee. Measurements additionally share existing application routing and
Traffic Control admission/shaping; see [measurement policy](probe-policy.md).

Periodic download tests reuse the verified streaming implementation, two-test
hard cap, and durable daily reservations. They default to once per hour and
at most one concurrent scheduled test; minimum interval is five minutes. Busy
or daily-budget-exhausted tests are skipped without network fallback or an
unlimited retry loop. They never reset a daily reservation by rescheduling.
Identical speed requests share a job only when concurrency, jitter and network
cost policy also match. Different execution settings can therefore generate
additional tests, subject to the same shared limits and daily budget.
While a test is running, its concurrency limit applies to the whole speed-test
class, even if another scheduled test permits a higher limit. Waiting tests are
admitted after a running test finishes or is canceled.

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

The same neutral-outcome classification protects generic node failure counters,
construction results and TCP/UDP circuit evidence. A quota or policy rejection
must not leave the generic Nodes status degraded while its channel remains
healthy. Policy markers are recognized through nested transport wrappers and
joined errors, including an outer `net.OpError{Op: "dial"}` around a block.
These errors still reach the caller; filtering health evidence does not grant
access or retry the operation. Deterministic observed-transport tests exercise
all three accounting paths and retain a real refused-dial positive control.

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

Application measurement policy is exposed as `policyState` in monitoring status.
Waiting measurements pause before Node construction; enforced measurements share
existing route and traffic controls. Throughput results include those configured
limits. The standalone/core scope is reported explicitly. No migration beyond
schema 19 is required.

## Upload resource measurements

Raw results: `docs/benchmarks/data/upload-measurement-2026-10-27/local.txt`.
Reproduce with:

```sh
go test ./pkg/net/latency ./pkg/node -run '^$' \
  -bench 'BenchmarkUploadStreamingBody|BenchmarkUploadBalancedRanking|BenchmarkSelectorConnectionCreation' \
  -benchmem -benchtime=300ms -count=3
```

On the recorded Ryzen 5 5600G/Linux environment, generating/discarding 1, 16 and
64 MiB used 1–2 allocations per iteration and approximately 123–3,418 amortized
bytes/op, rather than an allocation proportional to payload size. A bounded
scratch buffer/pool is reused; these numbers exclude TLS, network/kernel buffers,
process RSS and VPN framing, and represent random-byte generation throughput,
not a real-link speed result. Upload-aware balanced snapshots with 100/1,000
candidates took about 21–22/213–220 microseconds with 101/1,001 allocations. These
scores are compiled outside connection/packet forwarding. Manual TCP/UDP
creation remained about 324–339/95 ns in this fake-transport microbenchmark;
failover about 717–754/426–428 ns. Existing real loopback/churn qualification
remains separate. No runtime probes, ranking or SQLite reads were added to
packet/connection forwarding.

## Observed traffic window and recent TCP dial outcomes

`RuntimeStatus.trafficWindow` extends the existing node observer with a volatile
mean of observed logical transfer bytes, including probe/test traffic. Its
12-bucket ring follows the existing five-second sampling tick, covers at most
the last minute and reports actual sampled coverage as `windowMs`. Startup and
a partially filled ring can cover less than a minute. Intervals are weighted by
elapsed time; the oldest partial bucket is proportionally clipped, so this is
a bucketed estimate rather than an exact arrival-time trace. Idle zero-byte
intervals remain in the mean. Current per-tick Bps, window-average Bps and
active target/time-specific Mbps are distinct values in the Nodes detail view.

A sampling gap over ten seconds, reversed time, a wall/monotonic discrepancy over
one second or a decreased byte counter resets the ring. Status reads omit
snapshots older than ten seconds or from the future. This also covers platforms
whose monotonic clock pauses during suspend. Restarting starts a new window from
the existing persisted cumulative byte baseline; historical bytes do not become
a new traffic spike. Volatile windows add no backup/schema state or migration.

`recentTcpDials` reports the failure fraction and sample count of eligible
transport `connect` outcomes in the existing shared health history, filtered to
120 seconds and hard-bounded to its latest 64 entries. Other health events can
occupy that history, so this is a retained-sample summary. Later I/O failures,
application responses, active probe records and lazy UDP session creation are
excluded; no retained dial observations produce an omitted summary, not a zero
failure claim. Existing health/error classification determines which failures
enter the history. This ratio describes TCP dial creation, not complete request
success or UDP reachability.

The observer remains the sole window producer. Immutable atomic snapshots are
copied for status readers; no timers/workers, SQLite reads or rate calculations
are added to connection/packet forwarding. Rate fields are excluded from the
persisted totals, and `TestPassiveRateUpdatesDoNotCauseIdleSQLiteWrites` verifies
that changing idle window timestamps does not cause a SQLite write. Active
capacity ranking continues to use its existing independently fresh measurements.

Deterministic tests cover actual coverage, jitter weighting, partial clipping,
idle intervals, suspend/clock/counter resets, freshness, mutable-reader isolation,
concurrent reads, bounded dial classification and actual SQLite restart baseline.
The Node overview shows details in a collapsed section and retains existing
statistics/native status. EN/JA/KO unit and real-browser fixtures cover both old
servers with absent fields and separate observed/active metrics at 1440/360/320 px.

Raw resource results:
`docs/benchmarks/data/passive-window-2026-10-28/local.txt`. Reproduce with:

```sh
go test ./pkg/node -run '^$' \
  -bench 'BenchmarkPassiveRateSampling|BenchmarkSelectorConnectionCreation' \
  -benchmem -benchtime=300ms -count=3
```

The recorded Linux/amd64 run uses 776 bytes per window ring, plus its atomic
pointer and published snapshot. Updating 100/1,000 windows takes about
54/549–550 microseconds, with 5,600/56,000 allocated bytes per whole batch; the
existing tick performs these batches once per five seconds. The added cold
fields follow the existing hot counters. Fake-transport connection admission
retains the preceding allocation counts. These figures exclude complete process
RSS, SQLite traffic persistence, TLS/VPN resources and real-link capacity.


## Preferred recovery qualification

Pure strategy tests cover all three metric modes with return enabled/disabled,
initial choice, healthy/stale/unusable survivors, a recovered preferred node,
insufficient improvement, hold/cooldown and a third non-preferred improvement.
UDP uses its own comparable DNS evidence. A real SQLite/runtime fixture saves
and reloads the policy, checks actual fake-transport admission and bounded
suppression metrics, then enables return while preserving an established stream.
These tests are deterministic and require no public network. EN/JA/KO editor
coverage and real-browser Save/readback checks at 1440/360/320 px separately
verify the frontend configuration flow; synthetic browser fixtures are not a
backend reachability test.

The local Linux/amd64 Go 1.27.3 three-run benchmark uses three fresh samples per
candidate. At 100 candidates, median metric-ranking times for return-disabled /
return-enabled were 17.95/15.06 microseconds (RTT), 18.01/15.05 microseconds
(download) and 21.46/19.25 microseconds (balanced). At 1,000 candidates they were
189.46/161.70, 191.48/161.06 and 220.48/190.42 microseconds, respectively. Tracking
non-preferred alternatives adds no allocation: both settings use 1 allocation
for RTT/download ranking and 1,001 for 1,000-candidate balanced explanations.
The latter allocations already belong to candidate score components.

The same run gives median fake-transport TCP/UDP admission of 319/94 ns for
manual, 749/445 ns for failover and 786/476 ns for weighted selection; observed
UDP sends retain 0 B/op and 0 allocations. Ranking is snapshot work, separate
from these connection/packet paths. These measurements compare configurations
of this implementation, not before/after commits, maximum-history workloads,
peak process resources, physical VPN speed or remote latency. Commands and
[raw output](benchmarks/data/preferred-recovery-2026-10-28/local.txt) are retained.


## Runtime heap and lifecycle qualification

Snapshot compilation now reuses an immutable copy of each Node's existing
TCP/UDP histories until its observation sequence or transport generation changes.
All Selectors share that read cache in the original node counter. It introduces
no new statistics owner, database state, timers or connection/packet work.
The general status/export path still returns independent copies; a management
caller cannot modify cached selection evidence. Capacity updates remain visible
without a health update, and freshness is re-evaluated on every snapshot read.
Restore/reconfiguration invalidates the cache even when sequence values repeat.

Reproduce the resource fixture with:

```sh
go test ./pkg/node -run '^$' -bench '^BenchmarkSelectorRuntimeResources$' \
  -benchmem -benchtime=1x -count=3
```

Each operation creates a real SQLite deployment, opens the actual NodeRuntime,
loads 100 or 1,000 Nodes and 1 or 10 shared balanced Selectors, fills 64 TCP and
64 UDP observations per Node, and publishes 100 full runtime snapshots during 50 actual
unhealthy/healthy channel-state cycles (three network failures followed by three
successes per cycle). The fixture disables circuit admission to isolate the
channel FSM; separate circuit tests cover Open/Half-open/Closed transitions. It then retains 1,024 fake TCP streams and 1,024 fake
UDP sessions together, measures, closes every flow/runtime owner and measures
again after GC. The separate race test exercises 1,024 concurrent creators
through configuration/health churn. Neither fixture initializes a real VPN or
contacts the public network. The existing scheduler tests separately establish
the enabled-job worker/concurrency/cancellation bounds; this resource fixture
keeps periodic network tests off.

Three-run Linux/amd64 Go 1.27.3 medians below use decimal MB/GB. Retained Go heap
is the post-GC change relative to the seeded-and-closed SQLite fixture. Allocated
bytes include the complete lifecycle, fixture creation and 100 publications.

| Nodes / shared Selectors | Retained live heap | Cumulative allocated | Extra runtime goroutines | Extra goroutines after Close |
| --- | ---: | ---: | ---: | ---: |
| 100 / 1, previous implementation | 2.28 MB | 244.21 MB | 4 | 0 |
| 100 / 1, read cache | 4.25 MB | 52.36 MB | 4 | 0 |
| 1,000 / 1, previous implementation | 22.88 MB | 2.473 GB | 4 | 0 |
| 1,000 / 1, read cache | 42.55 MB | 548.21 MB | 4 | 0 |
| 1,000 / 10, read cache | 50.61 MB | 4.142 GB | 4 | 0 |

The single-Selector 1,000-Node lifecycle allocates about 78% fewer bytes by
avoiding repeated unchanged-history copies. The explicit tradeoff is a retained
immutable history copy, about 19.7 MB more for this worst-history fixture.
Additional Selectors share those histories but still allocate their own ranking,
score explanation, configuration and publication structures. The historical
4.142 GB cumulative result over 100 full publications preceded the preallocation
and node-map sharing measured below. The backend coalesces normal health-driven
publication on its existing runtime worker.

The 2,048 retained fake flows add approximately 181 KB of Go heap and no
additional goroutines in these cases. Post-Close Go heap differences fluctuate
by tens of KB because process caches/GC remain; zero owned goroutine growth does
not prove zero process memory retention. Forwarding allocation counts remain
80 B/1 allocation for fake TCP manual admission, 96 B/2 for fake UDP manual
admission, 272 B/5 and 288 B/6 for automatic failover/weighted admission, and zero
for observed UDP sends. Timing and full logs are retained.

[Before](benchmarks/data/selector-resources-2026-10-28/before.txt),
[after and shared Selectors](benchmarks/data/selector-resources-2026-10-28/after.txt)
and [forwarding](benchmarks/data/selector-resources-2026-10-28/forwarding.txt)
outputs retain fixture provenance. The before/after single-Selector comparison
uses the same fixture; the 10-Selector cases have no measured pre-change baseline.
These are Go heap/goroutine and cumulative-allocation measurements of an
in-memory transport fixture, not peak RSS, kernel socket memory, native VPN
resource cost, actual throughput or a production node-count guarantee.

## Fresh timeout summaries and HTTP safety qualification

Candidate status now exposes `healthSamples` and `timeoutRate`, derived while
compiling the existing snapshot. The denominator is the same policy-fresh health
window as `failureRate`; successful TCP response evidence is not counted twice.
Expired/future samples are excluded, and this count is separate from comparable
RTT samples. A timeout is an eligible failed dial/probe observation with a timeout
marker. Ordinary application I/O deadlines, local quota/policy rejection and
caller cancellation do not become remote timeout evidence. This is not a UDP
packet-loss estimate. The UI shows the ratio/count and explains that distinction;
older status responses without a denominator show unmeasured.

No additional statistics owner, persistence, timer, per-connection query or packet
work is introduced. The scalar summary adds no SQLite migration. Its deterministic
test includes timeout/non-timeout failures, duplicate response evidence, stale/
future observations and full expiry. A separate test alternates the small RTT
winner 100 times before a large improvement and reverse hold check.

The real local HTTP regression sends a POST that the first peer fully accepts
before resetting its TCP connection. It asserts that request reaches no alternate
peer. Only a separately submitted next request fails over; that peer returns
HTTP 403 and remains circuit-closed with no remote failure. This complements the
existing pinned TCP-stream and reply-only UDP session tests.

### Qualification after timeout projection

The final projection was remeasured with Go 1.27.3 on the same Ryzen 5 5600G
Linux/amd64 host. Three 200 ms ranking/admission runs give these medians:

| Compiled ranking | 100 candidates | 1,000 candidates | Allocations for 100 / 1,000 |
| --- | ---: | ---: | ---: |
| Failover | 15.4 µs | 155.5 µs | 20,480 / 204,800 B; 1 / 1 allocations |
| Lowest latency | 14.8 µs | 149.1 µs | 20,480 / 204,800 B; 1 / 1 allocations |
| Highest throughput | 14.9 µs | 149.7 µs | 20,480 / 204,800 B; 1 / 1 allocations |
| Balanced with components | 18.4 µs | 184.0 µs | 25,280 / 252,800 B; 101 / 1,001 allocations |

| New flow including GetTarget and actual fake Conn/PacketConn | TCP | UDP | TCP / UDP allocations |
| --- | ---: | ---: | ---: |
| Manual | 698 ns | 444 ns | 272 B/5; 288 B/6 |
| Failover | 872 ns | 550 ns | 328 B/8; 344 B/9 |
| Weighted | 919 ns | 595 ns | 328 B/8; 344 B/9 |

These compare modes in the current fake-transport fixture, not a before/after
optimization or physical connection latency. Cached-proxy connection measurements
are retained separately in the same raw admission file. The GetTarget-only rows
in the ranking file measure proxy creation: automatic admission is deferred and
those rows must not be presented as the complete dial cost. Observed UDP sends
still allocate zero bytes/objects.

A one-iteration resource recheck uses the same full-history/100-publication/
2,048-retained-fake-flow fixture described above. At 1,000 Nodes/one Selector it
retains 42.58 MB of Go heap and cumulatively allocates 551.54 MB; ten shared
Selectors retain 50.94 MB and cumulatively allocate 4.177 GB. All 100/1,000-Node
and 1/10-Selector cases add four owned runtime goroutines, no fake-flow goroutines,
and return to baseline after Close. The two scalar candidate summary fields make
snapshot records larger; this recheck is not another statistical before/after
comparison. Frequent full ranking remains allocation-heavy at many shared
Selectors. Neither fixture measures kernel/native-VPN resources or maximum
production deployment capacity.

```sh
go test ./pkg/node -run '^$' \
  -bench '^(BenchmarkSelectorRanking|BenchmarkSelectorTarget|BenchmarkObservedPacketSend)$' -benchmem -benchtime=200ms -count=3
go test ./pkg/node -run '^$' \
  -bench '^(BenchmarkSelectorConnectionCreation|BenchmarkSelectorNewFlow)$' -benchmem -benchtime=200ms -count=3
go test ./pkg/node -run '^$' -bench '^BenchmarkSelectorRuntimeResources$' -benchmem -benchtime=1x -count=1
```

[Ranking/packet](benchmarks/data/selector-qualification-2026-10-28/ranking.txt),
[admission](benchmarks/data/selector-qualification-2026-10-28/admission.txt),
[resource recheck](benchmarks/data/selector-qualification-2026-10-28/resources.txt).

### Snapshot allocation after preallocation and scratch reuse

Each configuration reload builds a fresh immutable Node map. Selectors compiled
in the same generation share that map, while a retained older snapshot continues
to reference its original generation. Candidate input slices are sized for each
network and reused between Selectors during one rebuild; published decisions,
candidate evidence, weights and orders retain independent data. This changes
snapshot compilation, not per-packet or per-connection selection; concurrent
reload, retained-snapshot and independent-decision tests cover the boundary.

On the same Linux/amd64, Go 1.27.3, Ryzen 5 5600G host, three independent
one-iteration runs of the full-history lifecycle fixture above give these medians
(decimal units):

| Nodes / Selectors | Before | After preallocation | After scratch reuse | Before / final retained Go heap |
| --- | ---: | ---: | ---: | ---: |
| 100 / 1 | 52.76 MB | 35.09 MB | 35.10 MB | 4.25 / 4.23 MB |
| 100 / 10 | 347.27 MB | 169.02 MB | 94.54 MB | 5.06 / 4.87 MB |
| 1,000 / 1 | 551.50 MB | 303.80 MB | 303.65 MB | 42.58 / 42.28 MB |
| 1,000 / 10 | 4.176 GB | 1.624 GB | 903.31 MB | 50.94 / 47.98 MB |

The middle three columns are cumulative allocation. The ten-Selector case now
allocates about 78% fewer bytes across fixture setup, 100 full publications and
shutdown; it still allocates substantially during frequent full rebuilds. Median
elapsed time for this fixture was 4.31 seconds before, 3.82 seconds after
preallocation and 3.83 seconds after scratch reuse. These local fake-flow numbers are not network
throughput or a production capacity guarantee. All cases still used four extra
runtime goroutines and returned to baseline after Close. Separate three-run
new-flow checks measured manual/failover TCP medians of 692/864 ns and UDP of
448/558 ns, with the same allocation counts as the preceding qualification.
[Before](benchmarks/data/selector-preallocation-2026-10-28/before.txt),
[after preallocation](benchmarks/data/selector-preallocation-2026-10-28/resources.txt),
[after scratch reuse](benchmarks/data/selector-scratch-2026-10-28/resources.txt), and
[new-flow results](benchmarks/data/selector-preallocation-2026-10-28/admission.txt)
contain the complete output and are reproducible using the commands above and
`go test ./pkg/node -run '^$' -bench '^BenchmarkSelectorNewFlow$' -benchmem -benchtime=300ms -count=3`.

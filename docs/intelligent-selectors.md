# Intelligent outbound selectors

Selectors keep their stable IDs and existing `nodeId`. Without an explicit
`policy`, selection remains manual. Existing deployments do not start periodic
probes or speed tests after this migration. The browser configures policy and
reads status; decisions are made by the backend while the browser is closed.

This first delivery supplies the selection engine, passive remote evidence,
manual measurements, persistence, and management UI. Scheduled probes,
Closed/Open/Half-open admission, periodic throughput tests, global health
defaults, and Prometheus additions are subsequent reliability work. Do not treat
eligibility filtering in this delivery as a complete circuit breaker.

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
with the selector's exact target qualify as comparable HTTPS RTT. UDP RTT uses
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

There is no automatic measurement traffic on desktop, Android, or metered links
in this delivery. Probe/speed targets are privileged administrator-chosen
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

# Shared measurements, budgets and metrics

Manual latency checks, scheduled health checks and active download tests use the
same NodeRuntime admission limit: global `probe.concurrency`, default 4, maximum
16. Per-selector scheduler limits and the speed-test subgroup cap (maximum 2)
remain additional limits. Admission fails immediately when busy, before outbound
construction or daily speed-budget reservation. Existing forwarding does not use
this registry. Lowering the limit lets admitted work exit normally and refuses
new measurements until the active count falls below the new limit.

The registry contains only admitted operations, with no per-node goroutine or
timer. Caller cancellation, node disable/removal/transport edits, credential
invalidation and runtime shutdown cancel the operation context. A cancellation
does not free its slot until the operation actually exits. Manual latency checks
have a 30-second overall deadline and now share the global probe bandwidth
limiter and 64 KiB logical byte allowance with periodic probes. Waiting for that
limiter is outside the RTT sample; local denial is not remote failure evidence.
Cached protocol-native status inspection performs no network operation.

The existing monitoring status adds `activeMeasurements` and `measurementLimit`.
`running` still counts scheduler work only, including jobs waiting for shared
admission. These values differ when a manual check is active. The UI displays
shared slot use and keeps scheduling opt-in.

## Download accounting and schema 20

Each active download durably reserves `maxBytes + 65536` bytes before network work.
The extra allowance covers TLS negotiation, HTTP requests/headers and transport
read-ahead. One atomic allowance caps all reads and writes through the selected
Node's logical stream boundary, across connections. The response-body sample
counter and its Mbps calculation remain independent; headers and TLS bytes are
not misreported as downloaded payload. No complete response is buffered.
Failed, cancelled and early-completed tests consume the full reservation. Busy
admission and invalid configuration consume none. The daily budget must fit one
inclusive reservation and is capped at 1 GiB per instance per UTC day. The
allowance is conservative: a large handshake/header exchange can exhaust it and
fail a test even if the body limit was not reached.

SQLite migration 20 adds `node_speed_budget.accounting_version`, default 1 for
existing rows. New reservations explicitly use version 2. If a version-1 row has
nonzero usage for the current UTC day, further tests refuse admission until the
next UTC day; old payload-only usage cannot be converted to a trustworthy
transport-inclusive total. Previous-day or unused rows can start version-2
accounting immediately. Restart and configuration export/restore cannot reset
this instance-owned budget. Changing the administrator's configured daily limit
still applies to the same durable total.

This is a logical Node-stream budget, not a physical-wire guarantee. VPN framing,
protocol control traffic, retransmissions and outbound construction/login traffic
are outside that stream boundary. Periodic expensive VPN startup remains disabled;
manual authentication follows the protocol's existing lifecycle. Traffic Control
continues to apply to measurement streams. Active download Mbps describes one
target and time under those controls, not internet link capacity.

## Prometheus

The existing `/metrics` endpoint includes `yuhaiin_outbound_` metrics:

| Suffix | Meaning |
| --- | --- |
| `selector_decisions` | Current selector counts by TCP/UDP, mode and bounded reason |
| `selector_switches_total` | Selection changes after initial choice |
| `selector_suppressed_total` | Evaluations held by cooldown/hysteresis |
| `circuits` | Shared circuit counts by TCP/UDP and Closed/Open/Half-open |
| `probes_total` | Manual/scheduled outcomes by bounded kind and outcome |
| `probe_rtt_seconds` | Successful complete probe duration, excluding admission wait |
| `speed_tests_total` | Active download outcomes |
| `active_download_mbps` | Successful active measurements, independent of business Bps |
| `last_speed_success` / `last_speed_timestamp_seconds` / `last_measured_download_mbps` | Latest completed test; consult success and time together |
| `measurements_active` / `measurement_limit` | Shared admission use and limit |
| `measurement_policy` | Waiting/enforced/standalone policy state |

Labels never include user, node, selector, URL or domain identities. Unknown
kinds/reasons normalize to `other`. Reasons and circuit gauges are precompiled
with the selector snapshot; scrapes do not rank candidates, query SQLite or start
probes. Gauges can lag a circuit transition until the next snapshot publication.
Counters survive resource deletion for the lifetime of the runtime; they reset
on process restart. Per-resource explanations/history remain in the authenticated
management API. A skipped reservation does not replace the last completed speed
result. Cancellation cannot publish a successful last-speed gauge.

Tests cover mixed entry-point admission, 1,000 simultaneous admission attempts,
limit reduction, real manual-probe cancellation on disable, streaming shared-byte
caps, unused-byte refunds, legacy migration/rollover, restart/export persistence,
finite label domains, seconds/Mbps units, concurrent scrape/snapshot updates and
a scrape with the sole SQLite connection held by another caller.

## Forwarding and ranking measurements

Linux/amd64 Ryzen 5 5600G, median of three 300 ms samples compared with the
probe-policy parent `360dd24c`. The same existing synthetic transports and
ranking inputs are used on both revisions. These are CPU microbenchmarks, not
physical-link throughput or total deployment resource qualification.

| Operation | Parent ns/op | Current ns/op | Current bytes / allocs |
| --- | ---: | ---: | ---: |
| SelectorNewFlow/manual/tcp | 757.70 | 729.30 | 272 / 5 |
| SelectorNewFlow/manual/udp | 458.60 | 476.00 | 288 / 6 |
| SelectorNewFlow/failover/tcp | 896.70 | 912.30 | 328 / 8 |
| SelectorNewFlow/failover/udp | 585.80 | 582.80 | 344 / 9 |
| SelectorNewFlow/weighted/tcp | 935.90 | 936.90 | 328 / 8 |
| SelectorNewFlow/weighted/udp | 608.80 | 623.60 | 344 / 9 |
| ObservedPacketSend | 4.07 | 4.31 | 0 / 0 |
| SelectorRanking/failover/100 | 12574.00 | 12885.00 | 16384 / 1 |
| SelectorRanking/lowest_latency/100 | 12024.00 | 12090.00 | 16384 / 1 |
| SelectorRanking/highest_throughput/100 | 11994.00 | 11630.00 | 16384 / 1 |
| SelectorRanking/balanced/100 | 15520.00 | 15487.00 | 21184 / 101 |
| SelectorRanking/failover/1000 | 119872.00 | 117801.00 | 155648 / 1 |
| SelectorRanking/lowest_latency/1000 | 116496.00 | 114356.00 | 155648 / 1 |
| SelectorRanking/highest_throughput/1000 | 116582.00 | 114521.00 | 155648 / 1 |
| SelectorRanking/balanced/1000 | 150748.00 | 155275.00 | 203648 / 1001 |

[Parent output](benchmarks/data/selector-2026-10-26/bounds-parent.txt) and
[current output](benchmarks/data/selector-2026-10-26/bounds-current.txt) retain
all repetitions. Ordinary UDP sends remain allocation-free. No measurement
admission, byte accounting or Prometheus observation runs per forwarded packet.

```sh
go test ./pkg/node -run '^$' -bench 'BenchmarkObservedPacketSend|BenchmarkSelectorNewFlow|BenchmarkSelectorRanking' -benchmem -benchtime=300ms -count=3
```

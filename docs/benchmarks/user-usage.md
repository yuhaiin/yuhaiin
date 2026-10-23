# User usage: resource measurements

Measured on 2026-10-23, Linux 7.2.6-zen2, Ryzen 5 5600G (6 cores/12 threads),
Go 1.27.3-X:nodwarf5, modernc SQLite on temporary `/tmp` files. Network cases use
`GOMAXPROCS=2` for both client and independent echo peer. Other host services were
left running; this is not a dedicated or frequency-isolated benchmark machine.

## Sustained real sockets

Each enabled/disabled case runs in its own compiled test process. The independent
peer removes shared-Go-scheduler effects from an in-process echo server. Each run
lasts at least eight seconds, exercising the one-second sampler and five-second
SQLite checkpoint; the order alternates across three repetitions. Both variants
retain the existing monitor/history/telemetry. Compilation and peer resource usage
are excluded. `wait4` records client process CPU time and peak RSS, including
startup, background work, final flush and shutdown. CPU/GiB uses uploaded plus
downloaded payload, as does TCP throughput. No profiling runs concurrently.

| Measurement (median of 3) | Usage disabled | Usage enabled |
|---|---:|---:|
| TCP, 16 KiB writes plus echoed reads | 2,763.64 MB/s | 2,902.89 MB/s |
| TCP CPU seconds / payload GiB | 0.3416 | 0.3493 |
| TCP peak RSS | 24,216 KiB | 24,264 KiB |
| UDP, 1,350-byte request plus reply | 21.608 µs/round trip | 21.603 µs/round trip |
| UDP CPU seconds / payload GiB | 4.6091 | 4.5916 |
| UDP peak RSS | 24,588 KiB | 26,488 KiB |
| UDP allocations | 64 B, 2 allocs/round trip | 64 B, 2 allocs/round trip |

TCP throughput varies from 2,683.82–2,999.54 MB/s disabled and
2,563.12–2,948.10 MB/s enabled. Its median CPU/GiB is about 2.3% higher with
usage, while median throughput is higher. This spread does not establish a
throughput improvement or a precise regression bound. UDP median latency is
nearly unchanged. RSS varies with runtime/SQLite caches; the extra 1.86 MiB in
the UDP median is not a per-connection memory estimate.

These are single-connection **loopback** forwarding measurements, not WAN,
encrypted-protocol, full-cone NAT capacity, high-churn or multi-tenant Gateway
throughput claims. Gateway attribution isolates authenticated credentials,
inbounds and client sources in its bounded transport pool; workloads that
previously shared an upstream connection across those scopes can require more
dials and need their own end-to-end qualification.

## Retained memory

A separate fixed-three-iteration benchmark opens 1,000 production monitor
connections, flushes existing metadata, forces GC, and compares live heap before
and after each burst. It closes and checkpoints them between iterations.

| Retained live heap | Disabled | Enabled | Increment |
|---|---:|---:|---:|
| Bytes per session | 606 | 1,246 | **640** |

That is approximately **0.61 MiB extra per 1,000 live sessions** for this fixture.
It excludes pending audit snapshots at later sample ticks, dimension/backlog growth,
GC reserve, SQLite caches, and kernel socket memory. It is not a total memory cap.
Credential/node/source string lengths and concurrency affect real deployments.

## Reproduce

From the backend checkout, build once and keep other builds/tests idle:

```sh
go test -c ./pkg/statistics -o /tmp/user-usage.test
go build -o /tmp/user-usage-peer ./scripts/bench/userusagepeer
python3 scripts/bench/user_usage.py \
  --binary /tmp/user-usage.test --peer-binary /tmp/user-usage-peer \
  --output /tmp/user-usage-results --repeat 3 --seconds 8 --procs 2

GOMAXPROCS=2 /tmp/user-usage.test -test.run='^$' \
  -test.bench='^BenchmarkUserUsage(Counter|Sample|Flush|Lifecycle)$' \
  -test.benchtime=1s -test.count=3 -test.benchmem
```

`BenchmarkUserUsageCounter` performs the exact existing atomic updates with the
worker off/on. `Sample` includes loading two counters, formatting checkpoints and
aggregating 100/1,000/10,000 live sessions. `Flush` includes sampling plus SQLite
transactions for 100/1,000 sessions. `Lifecycle` includes admission, payload,
closure, existing history and a **forced usage checkpoint on every burst** of
1/32 flows. That intentionally charges synchronous durability much more often
than the production five-second writer; do not present it as connection latency.

The disabled variant is the same feature binary with the recorder off. An
additional pre-change pipe/lifecycle/telemetry baseline was captured on the parent
revision; it is useful for detecting common forwarding changes, but is separate
from the paired enable/disable experiment above.

Raw independent-process samples: [JSON](data/user-usage/results.json),
[CSV](data/user-usage/results.csv), [environment](data/user-usage/environment.json).

## Sampling, persistence and churn costs

The separate `GOMAXPROCS=2`, 1-second × 3 microbenchmarks give these medians:

| Operation | Result |
|---|---:|
| Existing upload+download atomic updates, off/on | 32.12 / 31.96 ns, 0 B, 0 allocs |
| Sample 100 live sessions | 31.24 µs |
| Sample 1,000 live sessions | 363.58 µs, 23,464 B allocated |
| Sample 10,000 live sessions | 3.93 ms, 236,966 B allocated |
| Sample and persist 100 distinct session/dimension snapshots | 3.36 ms, 849,261 B allocated |
| Sample and persist 1,000 distinct snapshots | 33.94 ms, 8,299,508 B allocated |
| One-flow burst with forced existing/new persistence, off/on | 137.11 / 526.40 µs per flow |
| 32-flow burst with forced existing/new persistence, off/on | 8.05 / 74.93 µs per flow |

The successful transfer hot path stays at zero allocations. Persistence and audit
serialization have substantial transient allocations and lifecycle costs; the
640-byte retained sidecar figure must not be mistaken for total usage memory.
Production amortizes SQL work over five seconds instead of flushing every flow.
The microbenchmark's wall time is not a direct measurement of CPU utilization.
A large sampling pass holds the lifecycle mutex (not the transfer path), so new
admissions/closures can wait for that pass. A busy database can delay management
queries and other users of the same state store even though payload copying
continues. These costs deserve monitoring on resource-constrained/high-churn
hosts; this change does not promise zero resource impact.

Raw [microbenchmarks](data/user-usage/micro.txt) and
[parent baseline](data/user-usage/parent-baseline.txt) are retained for inspection.

## Profiling and common forwarding baseline

Separate 3-second CPU profiles attribute the 1,000-session sampling work mainly
to dimension-map hashing/updates and checkpoint formatting. The flush profile
spends about half its cumulative samples in SQLite's virtual machine, including
index updates and JSON validation. These profiles explain why sampling runs in
the background and why persistence is batched; they are not included in the
independent-process CPU measurements.

Inspect the [sampling CPU top](data/user-usage/profile-sample-top.txt) and
[flush CPU top](data/user-usage/profile-flush-top.txt). Reproduce with the compiled
test binary and `-test.cpuprofile=/tmp/sample.cpu` or
`-test.memprofile=/tmp/sample.mem`, selecting a single benchmark, then use
`go tool pprof -top /tmp/user-usage.test /tmp/sample.cpu`.

The original counted-pipe relay was also rerun with 12 Go processors, matching
the parent baseline (same fixture and 1-second × 3 repetitions). It remains at
zero allocations; see [after results](data/user-usage/pipe-after.txt). This is an
in-memory copy microbenchmark, independent of the real-socket results above.

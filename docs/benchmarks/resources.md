# Resource-governance measurements

Measured 2026-10-24, Linux amd64, Go `go1.27.3-X:nodwarf5`, Ryzen 5 5600G,
12 logical CPUs. Values are medians of three sequential runs without concurrent
tests/builds. CPU affinity and frequency are not pinned. Raw output is retained
in [data/resources](data/resources/). The compatibility baseline is Phase 1
commit `e941c8307b0da08fe32f62011ec8670e88473733`; current results correspond to
the resource-governance implementation committed with this report. Small
differences are not claims of statistical significance.

## Forwarding and admission

| Operation | Phase 1 baseline | Resource implementation | Heap allocation |
| --- | ---: | ---: | ---: |
| Unlimited datagram policy | 3.743 ns | 3.300 ns | 0 |
| Existing policy resolution | 48.09 ns | 48.20 ns | 0 |
| Governor packet admission | 17.03 ns | 18.22 ns | 0 |
| Governor session acquire/release | 67.08 ns | 72.81 ns | 32 → 48 B, 1 allocation |
| User + credential session acquire/release | N/A | 370.3 ns | 224 B, 5 allocations |
| User rate, no groups | N/A | 196.7 ns | 0 |
| User + 4 shared group rates | N/A | 390.3 ns | 0 |
| User + 64 shared group rates | N/A | 3,202 ns | 0 |
| Funded two-scope quota reserve/refund | N/A | 166.8 ns | 0 |

The base session's additional 16-byte allocation-class cost owns the optional
resource lease and its idempotent release. Identity governors add leases only
at admission, not per packet. Quota reservation measures a funded user/group
plan and refunds every request to isolate accounting from storage latency.
Many independently limited groups cost proportionally more locks/decisions;
64 memberships is a configured bound, not a constant-cost fast path.

TCP uses the production stream wrapper around an established plaintext IPv4
loopback echo connection, 16 KiB writes and concurrent draining. Reported MB/s
sums upload and download. There is no DNS, handshake, encryption or WAN link in
the timed loop. The resource fixture has one user and one shared group with high
rates; the quota fixture additionally has a monthly hard user quota. Its grant
and checkpoint worker uses an in-memory store, so results include worker
scheduling but do not qualify SQLite or disk throughput.

| TCP mode | Dual-direction throughput | ns / 16 KiB write |
| --- | ---: | ---: |
| No resource policy | 2,987 MB/s | 10,968 |
| User + shared group shaping | 2,530 MB/s | 12,953 |
| Shaping + live byte quota | 2,421 MB/s | 13,536 |

Active resource shaping costs about 15% of this particular local-loopback
throughput; adding quotas gives about 19% total reduction. No per-operation
allocations are reported after integer rounding; the quota worker amortizes
about 6 B per iteration. These are measured costs, not equivalent encrypted
gateway or physical-link results.

UDP uses the production full-cone NAT socket, send/reply queues and real IPv4
loopback echo peer. One 1,350-byte request/reply is outstanding at a time; MB/s
sums both directions. All fixtures carry the same authenticated identity.
Protected uses an enabled default-allow access policy. Resources adds user/group
rate buckets and session admission to that protected fixture; byte quotas are
measured separately above, not enabled in this UDP throughput fixture.

| UDP mode | Round-trip latency | Dual-direction payload rate | Allocations |
| --- | ---: | ---: | ---: |
| Access module absent | 23.79 µs | 113.52 MB/s | 254 B, 8 |
| Installed, access disabled | 25.31 µs | 106.66 MB/s | 254 B, 8 |
| Access protected | 25.35 µs | 106.49 MB/s | 254 B, 8 |
| Protected + resources | 27.07 µs | 99.75 MB/s | 254 B, 8 |

Resource shaping adds about 1.72 µs per request/reply over the protected case
without new packet allocations. Full-cone behavior, failed-write refunds and
quota isolation are covered by correctness/race tests independently of this
throughput fixture.

## State sharing and policy updates

Holding 1,024 identity session leases retains approximately **229 B/session**
after full GC, excluding precompiled policy/governor state, sockets, buffers,
access authorization state and historical statistics. The snapshot fixture uses
1,024 users, each in 64 groups, with daily/monthly/lifetime quotas on users and
groups. Shared rate buckets are also configured. It measures heap ownership
after GC; setup, GC and close are included in ns/op, so those timings are not
activation latency. Initial windows have no measured usage; SQLite caches and
durable grant records are excluded.

| Devices per user | Earlier unshared implementation | Final retained heap | Final bytes/credential |
| --- | ---: | ---: | ---: |
| 1 | 73.60 MB | 48.60 MB | 47,463 |
| 4 | 286.17 MB | 52.97 MB | 12,932 |
| 64 | Not measured | 140.31 MB | 2,141 |

The earlier measurements were captured during development before common
user/group quota-plan, shaping-slice and membership interning; they are not a
released revision. Their raw output is retained as optimization evidence.
Common plans now belong to the user once and devices retain only their own
quota segment. Four devices/user retain about 81% less memory than that earlier
implementation. The 64-device case reaches the 65,536-credential runtime bound;
140 MB is shared policy/budget state, not total memory for 65,536 network sockets.

With four forwarding workers across 1,024 users, recompile/publication takes a
median **2.783 ms/update**, allocates **3.74 MB/update**, and concurrently sustains
about **2.95 million policy checks/s**. This fixture includes policy preparation
and activation but excludes SQLite management commits and byte quotas. It tests
updates while forwarding; it is not a whole-system request-rate benchmark.

## Reproduction and recovery checks

Run the following separately on an otherwise idle host, with no concurrent
benchmark/test jobs:

```sh
go test ./pkg/net/trafficcontrol -run '^$' -bench '^(BenchmarkGovernorSession|BenchmarkGovernorPacketAdmit|BenchmarkDatagramPolicyUnlimited|BenchmarkPolicyResolve|BenchmarkIdentityDatagramPolicy|BenchmarkResourceAdmission)$' -benchmem -benchtime=1s -count=3
go test ./pkg/net/trafficcontrol/quota -run '^$' -bench '^BenchmarkQuotaReservation$' -benchmem -benchtime=1s -count=3
go test ./pkg/net/trafficcontrol -run '^$' -bench '^BenchmarkResourceTCPForwarding$' -benchmem -benchtime=1s -count=3
go test ./pkg/net/nat -run '^$' -bench '^BenchmarkAccessNATUDPRoundTrip$' -benchmem -benchtime=1s -count=3
go test ./pkg/net/trafficcontrol -run '^$' -bench '^(BenchmarkResourceIdleMemory1024|BenchmarkResourceSnapshotMemory)$' -benchmem -benchtime=1x -count=3
go test ./pkg/net/trafficcontrol -run '^$' -bench '^BenchmarkResourceUpdateUnderTraffic1024$' -benchmem -benchtime=1s -count=3
```

Abrupt-loss tests recover the last durable grant conservatively: an uncheckpointed
123-byte transfer against a 1,000-byte hard quota recovers a 1,000-byte charge,
never a fresh quota. Real SQLite clean-close/restart tests recover exactly the
123 measured bytes and return the unused 877 bytes. Separate tests hold a full
4 MiB of in-flight reservations and show that further slow writes cannot expand
the outstanding credit bound; refund wakes waiters. Lost acknowledgements retry
idempotently. See [recovery semantics](../resource-governance.md) for independent
dimension bounds and limits on accuracy.

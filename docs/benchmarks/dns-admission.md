# DNS cache admission and bounded upstream work

Measured on 2026-11-06 against `6dbb7b6f8627bc3d169582523fc119c25785a6e7`
(main before this change), using the same benchmark fixtures on both versions.
Linux amd64, AMD Ryzen 5 5600G, Go 1.27.3, `GOMAXPROCS=4`, ten samples per case.
The before and after runs were sequential, without other builds/tests running.

The change protects cached/local answers during upstream stalls. It is not a
universal throughput improvement: cold requests pay for a cache probe, preserved
request context, cancellation and a receipt-time deadline.

## Results

Medians from [before.txt](data/dns-admission-2026-11-06/before.txt) and
[after.txt](data/dns-admission-2026-11-06/after.txt). Logs are removed from those
files; benchmark samples and environment headers are retained. The complete
numeric comparison is in [summary.json](data/dns-admission-2026-11-06/summary.json).

| Case | Before | After | Latency change | Allocs before → after |
| --- | ---: | ---: | ---: | ---: |
| Cached datagram | 4.698 µs | 1.188 µs | -74.7% | 17 → 15 |
| Cached datagram, Prometheus enabled | 4.650 µs | 1.303 µs | -72.0% | 17 → 15 |
| Cached answer behind a 1 ms upstream stall | 1.075 ms | 4.946 µs | -99.5% | 30 → 19 |
| In-memory zero-TTL cold query | 6.033 µs | 9.497 µs | +57.4% | 29 → 39 |
| In-memory cold query, Prometheus enabled | 6.278 µs | 10.608 µs | +69.0% | 29 → 39 |
| Real loopback UDP zero-TTL cold query | 48.277 µs | 55.379 µs | +14.7% | 62 → 71 |
| Cached pipeline with 10,000 custom rules | 5.418 µs | 1.922 µs | -64.5% | 20 → 18 |
| Hosts pipeline with 10,000 custom rules | 5.398 µs | 1.846 µs | -65.8% | 23 → 21 |
| FakeIP pipeline with 10,000 custom rules | 6.112 µs | 2.326 µs | -62.0% | 26 → 24 |

The isolated saturation case uses one query permit, holds it with an uncached
query, then submits an already cached question. A timer releases the slow query
after 1 ms. Setup and waiting for the slow query after the cached reply are not
timed; the cached submission and completion are timed. This demonstrates removal
of head-of-line waiting, not a prediction of WAN or Android device latency.

The pipeline cases exercise custom responses, Hosts and FakeIP. Separate routing
integration tests verify that cache probes neither query upstream while matching
IP-based policy nor reuse the wrong Resolver after a route change. Cold UDP uses
a real loopback socket, echoes the question, and sets TTL to zero, so every
iteration sends an upstream query. In-memory cold results intentionally expose
admission overhead without hiding it behind network latency. Byte allocations
also increase on cold misses (1,929 → 2,810 B/op in memory; 3,611 → 4,391 B/op over
loopback UDP); cache-hit bytes are roughly unchanged (1,208 → 1,216 B/op).

These results qualify the intended benefit: cached/local DNS remains responsive
when upstream work is stalled. They do not establish a cold-query throughput,
phone battery, WAN throughput or physical-device network-handover improvement.

## Behavior and resource bounds

- Custom responses, Hosts, FakeIP and fresh/stale upstream caches can answer
  before the asynchronous miss queue. Resolver selection and ancillary IP/GeoIP
  lookups use cache-only mode. Missing policy evidence defers the request instead
  of guessing a route. Unknown resolver implementations safely take the miss path.
- The default upstream query limit remains 150. It is acquired inside the
  singleflight owner's operation, so duplicate waiters consume no extra upstream
  permit. Nested bootstrap DNS does not recursively acquire its parent's permit.
- Retained asynchronous UDP requests are separately limited to 150 + the configured
  pending budget (default 200), including duplicate waiters. The handoff ring is
  capped at exactly the configured limit rather than rounding 200 up to 256.
  Reducing that limit stops new admission until existing entries drain.
- Each accepted miss retains the caller's routing/authentication context and
  cancellation. Its ten-second total budget starts at receipt, including handoff
  and upstream-permit waits. Expired or canceled entries are skipped; overload
  rejects new misses without preventing cache hits.
- Accepted requests complete once, including shutdown. Synchronous rejection
  retains caller ownership. Cache hits may complete synchronously; their reply
  writer must not enqueue to a channel that can only be consumed after submission
  returns. The existing bounded stale-refresh policy is retained.
- `yuhaiin_dns_admission_results_total{result}` records `cache_hit`, `queued`,
  `queue_full`, `budget_full`, `canceled` and `expired`. Expired includes all total
  deadline expirations, not only queue expiration.
- `yuhaiin_dns_admission_wait_seconds{stage}` records `queue` handoff time and
  `upstream` query-permit wait, with fixed labels and seconds as the unit.

## Reproduction

Run the same commands in each source tree, sequentially:

```sh
GOMAXPROCS=4 go test ./pkg/net/dns/server -run '^$' \
  -bench '^BenchmarkDNS(DatagramAdmission.*|DatagramUDPMiss)$' \
  -benchmem -benchtime=200ms -count=10
GOMAXPROCS=4 go test ./pkg/net/dns/server -run '^$' \
  -bench '^BenchmarkDNSCachedBehindSlowQuery$' \
  -benchmem -benchtime=100x -count=10
GOMAXPROCS=4 go test ./pkg/resolver -run '^$' \
  -bench '^BenchmarkDNSDatagramPipeline$' \
  -benchmem -benchtime=100ms -count=10
```

For a baseline without changing the active checkout:

```sh
dns_before_dir=$(mktemp -d /tmp/yuhaiin-dns-before.XXXXXX)
git archive 6dbb7b6f8627bc3d169582523fc119c25785a6e7 | tar -x -C "$dns_before_dir"
cp pkg/net/dns/server/admission_fixture_test.go \
  pkg/net/dns/server/admission_benchmark_test.go "$dns_before_dir/pkg/net/dns/server/"
```

Run the commands above from that directory, then from this branch. The baseline
already contains `BenchmarkDNSDatagramPipeline`; the two copied files only supply
identical admission fixtures/benchmarks and do not change baseline implementation.

Regression tests cover fresh/stale cache saturation, duplicate waiters,
caller cancellation/values, receipt-time deadlines, overload, shutdown completion,
real UDP listener progress, routed cache selection, Hosts/FakeIP precedence,
bootstrap admission, and exact/wrapped/dynamically changed ring capacity.

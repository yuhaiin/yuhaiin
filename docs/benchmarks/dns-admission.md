# DNS cache admission and bounded upstream work

Measured on 2026-11-06 against `17a72978e8d67b46537be48b3320cdb06adf4aee`
(main before this change), using the same benchmark fixtures on every version.
Linux amd64, AMD Ryzen 5 5600G, Go 1.27.3, `GOMAXPROCS=4`, ten samples per case.
The runs were sequential; nothing else was built or tested concurrently.

The change protects cached/local answers during upstream stalls. It is not a
universal throughput improvement: cold requests pay for a cache probe, preserved
request context, cancellation and a receipt-time deadline.

## Results

Medians from [before.txt](data/dns-admission-2026-11-06/before.txt) (main) and
[after.txt](data/dns-admission-2026-11-06/after.txt) (this branch). Logs are
removed from those files; benchmark samples and environment headers are retained.
The complete numeric comparison is in
[summary.json](data/dns-admission-2026-11-06/summary.json).

| Case | Before | After | Latency change | Allocs before → after |
| --- | ---: | ---: | ---: | ---: |
| Cached datagram | 4.478 µs | 1.208 µs | -73.0% | 17 → 15 |
| Cached datagram, Prometheus enabled | 4.534 µs | 1.230 µs | -72.9% | 17 → 15 |
| Cached answer behind a 1 ms upstream stall | 1.074 ms | 4.926 µs | -99.5% | 30 → 19 |
| In-memory zero-TTL cold query | 5.694 µs | 6.708 µs | +17.8% | 29 → 38 |
| In-memory cold query, Prometheus enabled | 5.864 µs | 7.441 µs | +26.9% | 29 → 38 |
| Real loopback UDP zero-TTL cold query | 36.725 µs | 41.066 µs | +11.8% | 62 → 70 |
| Cached pipeline with 10,000 custom rules | 5.234 µs | 1.905 µs | -63.6% | 20 → 18 |
| Hosts pipeline with 10,000 custom rules | 5.173 µs | 1.860 µs | -64.0% | 23 → 21 |
| FakeIP pipeline with 10,000 custom rules | 5.872 µs | 2.296 µs | -60.9% | 26 → 24 |
| Routed miss, routing evidence cached, 10 rules | 13.444 µs | 17.002 µs | +26.5% | 69 → 81 |
| Routed miss, routing evidence cached, 200 rules | 36.905 µs | 41.149 µs | +11.5% | 263 → 275 |
| Routed cold miss, 10 rules | 18.098 µs | 28.781 µs | +59.0% | 96 → 116 |
| Routed cold miss, 200 rules | 48.292 µs | 60.492 µs | +25.3% | 290 → 310 |

The isolated saturation case uses one query permit, holds it with an uncached
query, then submits an already cached question. A timer releases the slow query
after 1 ms. Setup and waiting for the slow query after the cached reply are not
timed; the cached submission and completion are timed. This demonstrates removal
of head-of-line waiting, not a prediction of WAN or Android device latency.

The pipeline cases exercise custom responses, Hosts and FakeIP without routing.
Cold UDP uses a real loopback socket, echoes the question, and sets TTL to zero,
so every iteration sends an upstream query. In-memory cold results intentionally
expose admission overhead without hiding it behind network latency. Byte
allocations also increase on cold misses (1,929 → 2,601 B/op in memory; 3,609 →
4,179 B/op over loopback UDP); cache-hit bytes are roughly unchanged (1,208 →
1,216 B/op).

### Routed misses

`BenchmarkDNSRoutedMiss` runs the full custom response → FakeIP → Hosts → Route
pipeline with N host-list rules that never match, so each route decision
evaluates every rule. "Routing evidence cached" queries a TXT record whose
A/AAAA records (used by IP-based policy) are cached but whose own answer is not.
"Cold" uses a new name per iteration, so routing itself needs upstream addresses.

Before the routing fix ([before-routing-fix.txt](data/dns-admission-2026-11-06/before-routing-fix.txt),
`0ea5b7b1`), a miss matched the route twice: once in the cache-only probe and
again on the upstream path. Rule work and allocations roughly doubled.

| Case | main | Before routing fix | After | After vs before fix |
| --- | ---: | ---: | ---: | ---: |
| Evidence cached, 10 rules | 13.444 µs | 19.780 µs | 17.002 µs | -14.0% |
| Evidence cached, 200 rules | 36.905 µs | 68.008 µs | 41.149 µs | -39.5% |
| Cold, 10 rules | 18.098 µs | 33.698 µs | 28.781 µs | -14.6% |
| Cold, 200 rules | 48.292 µs | 93.534 µs | 60.492 µs | -35.3% |

Bytes per routed miss at 200 rules: 58,620 (main) → 121,923 (before fix) →
59,828 B/op (after). Two changes remove the second match:

- When the probe completes routing but misses the answer, it hands its route
  decision to the queued upstream query of the same request, which reuses it
  instead of repeating GeoIP, list, process and rule matching. The Resolver is
  looked up from the decision at use time, so a reload never leaves a request
  holding a replaced Resolver instance.
- When routing needs addresses that are not cached, the probe stops matching as
  soon as that is known, rather than evaluating the remaining rules for a
  decision that will be discarded.

The remaining cold overhead is roughly constant (about 10–12 µs here): the
admission handoff plus the cheap, deferred probe. It does not scale with rules.

These results qualify the intended benefit: cached/local DNS remains responsive
when upstream work is stalled. They do not establish a cold-query throughput,
phone battery, WAN throughput or physical-device network-handover improvement.

## Behavior and resource bounds

- Custom responses, Hosts, FakeIP and fresh/stale upstream caches can answer
  before the asynchronous miss queue. Resolver selection and ancillary IP/GeoIP
  lookups use cache-only mode. Missing policy evidence defers the request instead
  of guessing a route, and stops route matching early. A completed route decision
  is reused once by the same request's upstream query. Unknown resolver
  implementations safely take the miss path.
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
- Each fixed-label series is created on first use, so stages that never occur are
  not exported as zero series; later updates skip the label lookup.

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
GOMAXPROCS=4 go test ./pkg/resolver -run '^$' \
  -bench '^BenchmarkDNSRoutedMiss$' \
  -benchmem -benchtime=200ms -count=10
```

Benchmark logs share lines with benchmark names; keep each sample's name with
`awk '/^Benchmark/ {n=$1} /ns\/op/ {match($0, /[0-9]+[ \t]+[0-9.]+ ns\/op.*/); print n "\t" substr($0, RSTART)}'`.

For a baseline without changing the active checkout:

```sh
dns_before_dir=$(mktemp -d /tmp/yuhaiin-dns-before.XXXXXX)
git archive 17a72978e8d67b46537be48b3320cdb06adf4aee | tar -x -C "$dns_before_dir"
cp pkg/net/dns/server/admission_fixture_test.go \
  pkg/net/dns/server/admission_benchmark_test.go "$dns_before_dir/pkg/net/dns/server/"
cp pkg/resolver/routed_miss_benchmark_test.go "$dns_before_dir/pkg/resolver/"
```

Run the commands above from that directory, then from this branch. The baseline
already contains `BenchmarkDNSDatagramPipeline`; the copied files only supply
identical admission and routed-miss benchmarks and do not change baseline
implementation. The routing-fix comparison uses `0ea5b7b1` the same way, copying
only `routed_miss_benchmark_test.go`.

Regression tests cover fresh/stale cache saturation, duplicate waiters,
caller cancellation/values, receipt-time deadlines, overload, shutdown completion,
real UDP listener progress, routed cache selection, single route matching per
miss, early deferral before rule evaluation, Hosts/FakeIP precedence,
bootstrap admission, and exact/wrapped/dynamically changed ring capacity.

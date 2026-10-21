# FakeIP

Latest measurement: **2026-10-21**. Baseline `cb17c3bf`, bounded mapping cache
and transactional pool counts `2ad57265`. Linux amd64, Ryzen 5 5600G, Go
`1.27.2-X:nodwarf5`, default `modernc.org/sqlite` backend, local NVMe Btrfs, WAL
and synchronous NORMAL. The [retained summary](data/fakeip.summary.json) stores
all final samples and the earlier hardening/UDP comparisons.

These are local mapping and processing microbenchmarks. Upstream DNS, kernel
network I/O, encryption and physical-device throughput are outside the fixtures.

## Implementation

- Migration 16 creates a small `fakeip_pool_counts` table and backfills existing
  pools once. Insert, delete and pool-key update triggers maintain the count in
  the same SQLite transaction. Allocation reads a single count row instead of
  counting every mapping. Rollback restores mappings and counts together.
- Each active database/prefix has a lazy bidirectional cache with at most
  **4,096 entries**, further reduced for smaller pools. Both indexes point into
  one fixed slot array; cached domain strings are copied and limited to 253
  characters. Longer strings remain usable through the SQL fallback.
- Slot replacement is FIFO. It removes only the cached copy, preserving the
  durable mapping and active leases. This avoids updating a replacement list
  on every hot lookup. It does not add an in-memory index of eviction candidates.
- Handles sharing a database/prefix share locks, cache invalidation and leases.
  Management deletion invalidates both cache indexes only after successful
  deletion; new mappings enter the cache only after transaction commit.
- Cached activity samples queue the existing lazy durable touches. All owners'
  pending touches are flushed before address reuse. Closing one handle retains
  other handles' state; closing the last releases cache storage. Direct external
  SQL edits while a pool is running require restarting its owner to invalidate
  cached identities.

The cache retains the existing shared pool lock: cold allocation/SQL writes can
still delay concurrent hits. Isolated warm-hit timings do not bound mixed-load
request latency.

## Measurements

Six samples per revision, alternating before/after order in separate sequential
processes, without CPU affinity or an exclusive host. Main comparisons use
`GOMAXPROCS=1`; a separate parallel supplement uses 8. Benchstat version is
`v0.0.0-20261009192801-be2c69fb417e`.

Pool fixtures are seeded in one transaction outside timing. Hot tests warm all
4,096 mappings on **both** revisions before timing. New-domain tests perform
exactly 500 successful allocations, avoiding saturation failures being counted
as successful throughput. Other tests use one-second samples.

| Operation | Before | After | After allocations/op |
| --- | ---: | ---: | ---: |
| Warm domain hit | 7.510 us | 73.91 ns | 0 |
| Warm reverse hit | 7.589 us | 83.78 ns | 0 |
| Lease and release | 8.056 us | 382.5 ns | 3 |
| HTTPS rewrite, cached upstream and both IP families | 14.965 us | 643.0 ns | 9 |
| New domain, initially empty | 262.7 us | 260.8 us | 119 |
| New domain, initially 4,096 entries | 516.6 us | 302.8 us | 121 |
| New domain, initially 49,152 entries | 3.202 ms | 278.4 us | about 121 |
| Full pool, 4,096 recent entries | 311.4 us | 52.59 us | 79 |
| Full pool, 4,096 old leased entries | 3.856 ms | 3.534 ms | 24,655 |
| Cyclic 16,384-domain working set, no cache hits | 7.634 us | 8.300 us | 29 |

Warm domain/reverse lookups improved about **102x/91x** and dropped from 28
allocations to zero. Large-pool new allocations improved about **11.5x**. The
empty-pool time difference is not significant (p=0.937); the other listed time
changes have p=0.002. New allocations use about 5.4--5.6 KiB/op versus
4.7--4.9 KiB/op, despite fewer allocation objects.

The deliberately cache-hostile cyclic workload is **8.72% slower**, with one
extra allocation. Bounded caching is most beneficial with repeated mappings;
its cold SQL fallback includes index maintenance and string-copy overhead.

Eight-worker parallel domain hits measured 44.92 ns/op in aggregate, with a
wide 39% confidence range. Parallel lease/release measured 384.4 ns/op versus
9.046 us/op before. These are aggregate wall time divided by completed
operations, not individual-request latency or p95. A separate six-second lease
run, allowing the touch worker to flush during timing, measured 388.8 ns/op,
112 B/op and 3 allocations/op.

## Memory

Retained cache heap measured after GC, with source strings outside the
measurement and the populated cache kept alive, six samples:

| Fully populated cache | Bytes per pool | IPv4 and IPv6 pools together |
| --- | ---: | ---: |
| Short `domain-N.example` names | 840,984 (0.80 MiB) | about 1.60 MiB |
| 253-character names | 1,791,336 (1.71 MiB) | about 3.42 MiB |

These include the slot array, both indexes and owned domain strings. They are
cache heap measurements, not total process RSS or a bound on allocator headroom,
SQLite buffers, pending touches or existing connection leases. Cache buffers are
allocated only when first populated; their entry limit does not grow with the
persisted pool's 65,536 or more mappings. No per-persisted-entry eviction index
was added.

## Remaining cost

The all-leased exhaustion case still scans every eligible SQL candidate and
allocates about 419 KiB per failure. The earlier 256-candidate cap could falsely
report exhaustion when candidate 257 was available. Full scanning remains
necessary for correctness with the present SQL design. Reducing candidate
materialization/index sorting can be investigated separately; the cache/count
changes do not implement the proposed in-memory eviction index.

The earlier cached UDP sender optimization in `414c7abc` measured
109.75 to 79.81 ns/op, 27.28% less time with zero allocations. It is unchanged by
this pool optimization. Its fixture includes source lease admission and a
warmed target cache using a sink without I/O; native UDP tests separately verify
one shared socket per source and unsolicited replies.

## Reproduction and validation

Copy `pkg/net/dns/fakeip/benchmark_test.go` from `2ad57265` into an isolated
`cb17c3bf` worktree, and use the same source at both revisions. Set `TMPDIR` to
the filesystem being evaluated. Run revisions sequentially; for the retained
comparison, each of six rounds alternated which revision ran first.

```sh
go test ./pkg/net/dns/fakeip -run '^$' \
  -bench '^BenchmarkFakeIP(HotPath|Exhausted|HTTPS)$' \
  -benchmem -benchtime=1s -cpu=1 -count=6
go test ./pkg/net/dns/fakeip -run '^$' \
  -bench '^BenchmarkFakeIPHotPath$/^parallel_(domain|lease_release)$' \
  -benchmem -benchtime=1s -cpu=8 -count=6
go test ./pkg/net/dns/fakeip -run '^$' \
  -bench '^BenchmarkFakeIPNewDomain$' \
  -benchmem -benchtime=500x -cpu=1 -count=6
go test ./pkg/net/dns/fakeip -run '^$' \
  -bench '^BenchmarkFakeIPCacheChurn$' \
  -benchmem -benchtime=1s -cpu=1 -count=6
# Memory benchmark exists only in the optimized revision.
go test ./pkg/net/dns/fakeip -run '^$' \
  -bench '^BenchmarkFakeIPCacheMemory$' -benchtime=1x -cpu=1 -count=6
```

Race checks pass for DNS, FakeIP, resolver, NAT, SQLite storage, store, app,
inbound and Gateway. The SQLite CI matrix passes for both modernc (CGO disabled)
and mattn (CGO enabled), including statistics, migration and node tests. Coverage
includes warm lookup without SQL, bounded replacement, lease protection after
cache replacement, shared-handle deletion/touches/close, rollback, concurrent
reads/leases/deletion, old-schema count backfill and transactional count updates.

Formatting, golangci-lint v2.15.0 and `go fix ./...` pass without further source
changes.

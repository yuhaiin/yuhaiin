# FakeIP

Measured **2026-10-21** on Linux amd64, Ryzen 5 5600G, Go
`1.27.2-X:nodwarf5`, using the default `modernc.org/sqlite` backend. The database
was on the local NVMe Btrfs filesystem, with WAL and synchronous NORMAL.
These are mapping and packet-processing microbenchmarks; upstream DNS, kernel
network I/O, encryption and real-device throughput are outside the fixtures.

The [retained summary](data/fakeip.summary.json) contains every final sample.
The PR baseline is `54badcdb`; correctness repairs are `0aa2909f`; the cached UDP
lease optimization and benchmark harnesses are `414c7abc`.

## Method

- Six samples per revision, alternating before/after order, in separate,
  sequential processes. No CPU affinity was applied; this was not an exclusive
  host. Medians and significance were calculated with benchstat
  `v0.0.0-20261009192801-be2c69fb417e`.
- Pool fixtures contain 4,096 mappings, seeded in one transaction outside the
  timed section. Positive lookups use prebuilt domain strings and IP addresses.
- Hot lookups, HTTPS and exhaustion use one-second samples at `GOMAXPROCS=1,8`.
  Parallel benchmarks use `RunParallel`; their ns/op is aggregate wall time per
  completed operation, not individual-request latency.
- New-domain tests use exactly 500 successful allocations per sample, with
  initial occupancies 0, 4,096 and 49,152 and a capacity of 65,535. This prevents
  saturation failures from being counted as successful allocation throughput.
- HTTPS uses a cached upstream response with ALPN and IPv4 hints, with IPv6
  enabled. Both address families already have mappings. The fixture includes
  the production response copy and parameter rewrite.
- Exhaustion tests distinguish recent mappings from mappings older than two
  hours that are all actively leased. Every timed allocation must fail.
- Cached UDP tests include the sender's lease admission and a warmed address
  cache, using a lease-capable proxy and a sink without I/O. They use one
  session and do not perform reverse SQL lookups per packet. Separate native
  UDP tests verify shared sockets and unsolicited replies.

## Pool measurements

Single-worker medians; lower is better. The UDP-only optimization in `414c7abc`
does not change the pool implementation measured at `0aa2909f`.

| Operation | PR baseline | Repaired | Repaired allocations/op |
| --- | ---: | ---: | ---: |
| Domain hit | 7.052 us | 7.000 us | 28 |
| Reverse hit | 7.079 us | 7.050 us | 28 |
| Lease and release | 7.392 us | 7.400 us | 31 |
| HTTPS response rewrite | 13.705 us | 13.789 us | 65 |
| New domain, initially empty | 256.8 us | 251.4 us | 141 |
| New domain, initially 4,096 entries | 518.9 us | 513.4 us | 143 |
| New domain, initially 49,152 entries | 3.163 ms | 3.188 ms | 143 |
| Full pool, all recent | 323.9 us | 312.0 us | 102 |
| Full pool, 4,096 old leased entries | 2.131 ms | 3.651 ms | 24,679 |

Domain/reverse/lease/HTTPS differences were not statistically significant in
these samples. HTTPS allocations fell from 68 to 65. Serial `RunParallel`
lease/release rose 1.62% (p=0.017); its eight-worker result was not significant.
Eight-worker parallel domain lookup was 9.490 us/op versus 7.412 us/op with one
worker: this SQL-backed path does not scale with more goroutines. The shared
database currently permits one open connection.

The all-leased exhaustion case is a material cost of the correctness repair:
the old SQL query stopped after 256 candidates, which could falsely report
exhaustion when candidate 257 was available. The repaired query checks all
eligible mappings. In the 4,096-entry fixture this costs 71% more time and
419.5 KiB/op versus 29.5 KiB/op. This is an optimization target; restoring a
candidate cap would restore the bug.

## Cached UDP optimization

The first comparison measured the PR's original cached sender at 57.80 ns/op
and the repaired sender at 107.30 ns/op. A separate six-sample paired comparison
then measured the repaired sender at **109.75 ns/op** and the optimized sender
at **79.81 ns/op**: **27.28% less time** (p=0.002), with **zero allocations** in
both. These are processing costs per cached packet, not measured bandwidth.

The optimization skips duplicate acquisition/cleanup work for a lease already
owned by a retained mapping or pending resolution. New destinations still
acquire before dial/dispatch; failed admissions and failed resolutions release
their leases; retained leases are released after session shutdown. Cached sends
do not mark the same lease retained again.

## Profiles and remaining opportunities

CPU profiles were collected separately from the comparison runs. Profiles also
include fixture setup, which took about 20% of the new-domain profile; the
benchmark timings above exclude it.

1. **Avoid counting the entire pool on every new allocation.** At roughly
   49,000 entries, `entryCount` accounts for 74.25% of all sampled CPU and about
   94% of the cumulative allocation path. A counter maintained transactionally
   with insert, eviction and management deletion is the strongest next target.
   It needs consistent initialization and rollback handling; an unsynchronized
   in-memory count would risk incorrect capacity decisions.
2. **Reduce SQLite work on positive lookups.** `getIP` accounts for 95.10% of
   sampled hot-path CPU. Query/scan/close and WAL locking dominate; `fcntl`
   accounts for about 25% cumulatively. A bounded bidirectional mapping cache
   could avoid most of this work. Its eviction, deletion, range-change and lease
   ownership rules must remain atomic with the durable mapping state.
3. **Reduce candidate materialization in saturation scans.** `evictLRU` accounts
   for 87.36% of sampled all-leased exhaustion CPU. It decodes every candidate's
   domain and IP before checking whether it is leased. Fetching only identity
   needed for rejection, retrieving the domain only for a chosen row, and
   evaluating an index that also covers the `created_at` ordering are focused
   experiments. Scanning must still reach an available candidate beyond 256.

The larger SQLite changes above are recommendations, not implemented speedups.
The only performance change in this measurement is cached UDP bookkeeping.

## Reproduction

Use the same benchmark source at both revisions. For `54badcdb` and `0aa2909f`,
copy `pkg/net/dns/fakeip/benchmark_test.go` and
`pkg/net/nat/fakeip_benchmark_test.go` from `414c7abc` into an isolated worktree.
Run the revisions sequentially, alternating which revision runs first in each
of six rounds. Set `TMPDIR` to a directory on the filesystem being evaluated.

```sh
go test ./pkg/net/dns/fakeip -run '^$' \
  -bench '^BenchmarkFakeIP(HotPath|Exhausted|HTTPS)$' \
  -benchmem -benchtime=1s -cpu=1,8 -count=6
go test ./pkg/net/dns/fakeip -run '^$' \
  -bench '^BenchmarkFakeIPNewDomain$' \
  -benchmem -benchtime=500x -cpu=1 -count=6
go test ./pkg/net/nat -run '^$' \
  -bench '^BenchmarkNATFakeIPCachedSend$' \
  -benchmem -benchtime=1s -cpu=1 -count=6
```

For CPU profiles, run one fixture at a time; do not include those timings in
the comparison. For example:

```sh
go test ./pkg/net/dns/fakeip -run '^$' \
  -bench '^BenchmarkFakeIPHotPath$/^domain$' \
  -benchtime=5s -cpu=1 -cpuprofile=/tmp/fakeip-hot.cpu
```

Race tests for FakeIP, NAT and resolver pass after the UDP optimization,
including full-cone socket/reply behavior, migration and failure cleanup.
golangci-lint v2.15.0 reports zero issues; `go fix ./...` and formatting checks
produce no further changes.

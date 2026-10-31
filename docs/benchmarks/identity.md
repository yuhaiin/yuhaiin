# Traffic identity microbenchmarks

Measured 2026-10-23 on Linux amd64, AMD Ryzen 5 5600G (12 logical CPUs), Go
1.27.3-X:nodwarf5. Baseline is backend main `65f367c6`. Baseline and changed
programs ran sequentially in separate source directories, without the test and
build jobs running concurrently. The host was not isolated or frequency-pinned.
These are processing microbenchmarks, not TCP/UDP forwarding or WAN throughput.

For the existing benchmarks, five samples at 500 ms per sample:

| Benchmark | Before median | After median | Allocation counts |
| --- | ---: | ---: | --- |
| Proxy credential verification | 114.8 ns | 114.9 ns | 0 B, 0 allocs, both |
| Existing 30,000-host matcher | 524.5 ns | 551.1 ns | 48 B, 3 allocs, both |

The host matcher was about 5.1% slower in this sequential run. That benchmark
exercises the unchanged host trie lookup; this measurement does not establish a
cause or an end-to-end forwarding regression. Its raw samples are retained rather
than describing all existing paths as unchanged in performance.

New identity group leaf results below use the final adaptive lookup: a small
policy ID set binary-searches the authenticated sorted memberships; otherwise
memberships probe a precompiled set. The matching ID is deliberately last among
64 memberships in the worst-case setup. Three samples per case, 500 ms each:

| Policy IDs | Authenticated memberships | Median | Allocations |
| ---: | ---: | ---: | --- |
| 1 | 1 | 26.29 ns | 0 |
| 1 | 64 | 40.53 ns | 0 |
| 64 | 1 | 24.74 ns | 0 |
| 64 | 64 | 476.2 ns | 0 |
| 1,024 | 1 | 25.70 ns | 0 |
| 1,024 | 64 | 525.9 ns | 0 |

The initial membership-scan implementation cost about 626 ns for a one-ID policy
against 64 memberships. Adaptive lookup reduces that case to about 41 ns.

A separate parallel microbenchmark rotates across 1,024 immutable user/credential
contexts on 12 workers. It measured approximately 3.92 ns/op aggregate throughput
per operation, with zero allocations. That is a throughput metric across workers,
not single-request latency and not 1,024 live sockets. It does not establish
admission overhead, TCP/UDP transfer performance, total memory per connection,
or behavior under live authorization updates. Those acceptance workloads remain
part of the subsequent enforcement/resource phases.

Reproduce the existing cases separately in the baseline and changed directories:

```sh
go test ./pkg/management/auth ./pkg/route -run '^$' \
  -bench '^(BenchmarkProxyCredentialVerification|BenchmarkHostMatcher)$' \
  -benchmem -benchtime=500ms -count=5

go test ./pkg/route -run '^$' \
  -bench '^(BenchmarkIdentityGroupMatch|BenchmarkIdentityMatch1024ConcurrentUsers)$' \
  -benchmem -benchtime=500ms -count=5
```

Raw results: [before](data/identity/before.txt),
[after, including the initial group lookup](data/identity/after.txt),
[final optimized group lookup](data/identity/optimized-groups.txt).

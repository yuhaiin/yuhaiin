# Access-policy qualification

The benchmark fixtures are committed with the implementation. Raw output lives
in [data/access](data/access/). Measurements use Linux amd64, Go
`go1.27.3-X:nodwarf5`, Ryzen 5 5600G, 12 logical CPUs. Runs are sequential without
concurrent test/build jobs. Values below are medians of three runs; CPU frequency
and affinity are not pinned, so small differences are observations, not a claim
of statistical significance or remote encrypted throughput.

## What is measured

- Complete ordered policy evaluation combines group, destination CIDR, UDP and
  port conditions. The 1,024-rule case scans to the last matching rule with
  64 group memberships. Neither uses SQL or a trace formatter.
- Cached datagram checks validate identity lifetime, the current epoch and an
  exact original/resolved endpoint key. They do not copy rule trees or memberships.
- Admission opens one session, authorizes one target and releases it, including
  cancellation registration. Setup is outside forwarding throughput measurements.
- A policy update recompiles, publishes and revalidates 1,024 retained sessions.
  It excludes SQLite commit. Memory uses 1,024 simultaneously retained session
  authorizations with a full GC, excludes separately prepared identity objects,
  and excludes sockets, queues, application buffers and existing statistics state.
- TCP is one established plaintext loopback echo stream, 16 KiB writes with
  concurrent draining. Reported MB/s sums upload and download. It measures the
  production authorization wrapper, including its preserved half-close and
  ReaderFrom/WriterTo paths, without DNS, encryption, a physical bottleneck or
  connection handshakes on each iteration.
- UDP is the production NAT source/queues/socket adapter with real IPv4 loopback
  sockets, one outstanding 1,350-byte request/reply per iteration. Reported MB/s
  sums both directions. It measures round-trip processing, not WAN capacity.
  Absent, installed-disabled and protected cases all carry the same authenticated
  identity. Protected send and reply checks use a default-allow policy; detailed
  expression evaluation is measured separately. Cached authorizations still
  revalidate on policy changes.

## Cache optimization

The initial implementation allocated a map bucket for every session's first
endpoint. The final version retains that first endpoint directly and adds a map
only for additional endpoints. Both retain exact comparable keys; hashes alone
are never authorization evidence. Snapshot publication still rechecks all keys.

| Operation | Initial map cache | Single-target cache |
| --- | ---: | ---: |
| Admission allocation | 1,777 B, 7 allocations | 480 B, 6 allocations |
| Admission latency | 856.5 ns | 564.8 ns |
| Recompile + revalidate 1,024 sessions | 216.9 µs | 123.8 µs |

Raw initial files have a `-map` suffix. Before the cache change, removing
unconditional IP string formatting from disabled tracing also removed one
16-byte allocation from full policy evaluation. Regression tests assert zero
allocations for complete untraced evaluation and cached checks.

| Final operation | Median | Allocations |
| --- | ---: | ---: |
| Complete group/CIDR/protocol/port evaluation | 143.3 ns | 0 B, 0 allocs |
| Cached datagram authorization | 83.48 ns | 0 B, 0 allocs |
| 1,024-rule scan, 64 group memberships | 53.72 µs | 0 B, 0 allocs |
| Retained authorization, 1,024 simultaneous sessions | 498.9 heap B/session | includes registry share |
| UDP capability absent | 23.82 µs / round trip, 113.37 MB/s | 254 B, 8 allocs |
| UDP installed, disabled | 25.60 µs, 105.49 MB/s | 254 B, 8 allocs |
| UDP protected | 25.64 µs, 105.32 MB/s | 254 B, 8 allocs |

Protected UDP has about 7.6% slower round-trip processing than the absent
capability in this run; installed-disabled is about 7.5% slower. Three authorization
checks, identity lifetime checks and revocable association ownership are retained
on purpose. No additional packet allocation was measured. The single-target cache
reduced cached checks from 110.9 ns to 83.48 ns and retained authorization memory
from 1,795 to 499 heap bytes per session (about 72%). The initial map-based protected
UDP median was 25.64 µs; that small aggregate difference is within unpinned loopback
noise and does not establish an optimization gain in real-network throughput.

TCP medians were 3,067 MB/s absent, 3,087 MB/s installed-disabled and 3,117 MB/s
protected, with zero steady-state allocations in all three cases. The protected
case was within the range of the absent samples (2,989–3,120 MB/s). This establishes
no measured sustained TCP regression in this fixture, not a speedup guarantee.

This qualification does not represent 1,024
real remote users or sockets: the 1,024-user scenario measures retained policy
state and updates. There is no end-to-end enterprise WAN capacity claim.

With four workers continuously checking the same 1,024 retained authorizations,
recompile/publication/revalidation took a median 157.2 µs while workers completed
about 37.7 million cached checks/second in aggregate. This is a synthetic CPU
contention scenario, not per-user latency or packet throughput. All authorizations
remained allowed; the concurrent-update benchmark fails on an unexpected denial.

## Existing optional-free path versus the foundation commit

`nat-before.txt` uses foundation commit `d4c69282`; `nat-after.txt` uses this change
with no access capability installed. The cached-send fixture has a sink socket
and no actual I/O, so its MB/s is payload bookkeeping capacity only.

| Cached send | Before | After | Heap allocation |
| --- | ---: | ---: | ---: |
| IP | 55.22 ns | 57.38 ns | 0 in both |
| Mapped IP | 55.21 ns | 57.18 ns | 0 in both |
| Remote domain | 49.02 ns | 50.34 ns | 0 in both |

The added optional authorization branch/helper costs about 1.3–2.2 ns (2.7–3.9%)
in this microbenchmark. It is separate from the protected real-socket round-trip
cost above; neither result is a remote encrypted forwarding measurement.

## Reproduction

Run each command while the machine is otherwise idle. Do not parallelize these
with each other, race tests or builds:

```sh
go test ./pkg/net/accesscontrol -run '^$' -bench 'BenchmarkAccess(PolicyEvaluation|CachedDatagram|Admission|Update1024|LargePolicy1024)$' -benchmem -benchtime=500ms -count=3
go test ./pkg/net/accesscontrol -run '^$' -bench '^BenchmarkAccessUpdateUnderTraffic1024$' -benchmem -benchtime=500ms -count=3
go test ./pkg/net/accesscontrol -run '^$' -bench '^BenchmarkAccessIdleMemory1024$' -benchmem -benchtime=5x -count=3
go test ./pkg/net/accesscontrol -run '^$' -bench '^BenchmarkAccessTCPForwarding/(Absent|Disabled|Protected)$' -benchmem -benchtime=700ms -count=3
go test ./pkg/net/nat -run '^$' -bench '^BenchmarkNATCachedSend$' -benchmem -benchtime=500ms -count=3
go test ./pkg/net/nat -run '^$' -bench '^BenchmarkAccessNATUDPRoundTrip/(Absent|Disabled|Protected)$' -benchmem -benchtime=700ms -count=3
```

# DNS response pipeline

Latest measurement: **2026-10-21**. Linux amd64, AMD Ryzen 5 5600G, Go
`1.27.3-X:nodwarf5`, GOMAXPROCS=12, default modernc SQLite backend. The
[retained summary](data/dns-responses.summary.json) contains every final sample
and the CPU/allocation profile summaries.

The comparison keeps the new response rules and benchmark fixtures identical.
The baseline substitutes the original DNS client, UDP transport and server
source files from `8bb71abd`; the optimized version uses this change's files.
Those three baseline files are also identical at the initial `86875f51` base.
This measures the packet-processing optimizations, including the local-answer
fast path, rather than attributing the difference to a different answer source.

Five samples per comparison, separate sequential processes, 500 ms packet
samples and one-second client/key samples. UDP-only and rule-index supplements
use three 500 ms samples. Tables show medians. The host was shared, without CPU
affinity; small timing differences should not be treated as significant.

## Full datagram processing

`BenchmarkDNSDatagramPipeline` includes packet creation and reference handling,
the DNS-agent queue and worker dispatch, question decoding, custom rules,
FakeIP/hosts/upstream-cache selection, reply construction, encoding and the
write-back callback. There are no kernel sockets in this table. The upstream is
a deterministic local transport; caches and the SQLite FakeIP mapping are warm.

Unless stated otherwise, fixtures contain **10,000 rules**. A miss continues
through the existing DNS pipeline. Rule matches use their actual configured
NXDOMAIN or AAAA response.

| Path | Before | After | B/op before → after | Allocations before → after |
| --- | ---: | ---: | ---: | ---: |
| Cached A, wrapper omitted | 5.748 us | 4.947 us | 1,305 → 1,257 | 22 → 20 |
| Cached A, empty rules | 5.768 us | 4.967 us | 1,305 → 1,257 | 22 → 20 |
| Cached A, 10,000 rule miss | 5.978 us | 5.314 us | 1,305 → 1,256 | 22 → 20 |
| NXDOMAIN match, 10 rules | 5.013 us | 2.542 us | 1,280 → 608 | 18 → 9 |
| NXDOMAIN match, 1,000 rules | 5.105 us | 2.591 us | 1,281 → 608 | 18 → 9 |
| NXDOMAIN match, 10,000 rules | 5.200 us | 2.560 us | 1,312 → 608 | 18 → 9 |
| Custom AAAA match | 5.584 us | 3.058 us | 1,344 → 608 | 20 → 11 |
| Static hosts A | 5.874 us | 5.279 us | 1,464 → 1,368 | 25 → 23 |
| Warm FakeIP A | 9.444 us | 5.892 us | 1,753 → 1,641 | 29 → 26 |

The 10,000-rule NXDOMAIN and AAAA paths take about **51%/45% less time** and
allocate about **54%/55% fewer bytes** in these fixtures. The disabled wrapper
adds about 20 ns in these samples, without adding allocations. A 10,000-rule
miss adds about 0.35 us relative to empty rules. The matching index avoids a
linear scan of the configured rules.

## Real UDP and upstream I/O

`BenchmarkDNSUDPPipeline` adds a real loopback UDP client and listener to the
same resolver fixtures. It uses the server's actual `HandleUDP` processing
method and synchronous write-back, without the separate interception queue.
These are serial round-trip latencies, not parallel throughput measurements.

| Path | After | B/op | Allocations/op |
| --- | ---: | ---: | ---: |
| Cached A, 10,000-rule miss | 22.648 us | 1,181 | 21 |
| Custom NXDOMAIN | 17.172 us | 532 | 10 |
| Custom AAAA | 17.342 us | 532 | 12 |
| Static hosts A | 22.954 us | 1,289 | 24 |
| Warm FakeIP A | 22.855 us | 1,565 | 27 |

`BenchmarkDNSRoutedUDPPipeline` additionally uses the real route matcher,
SQLite-backed route snapshot, resolver manager and UDP upstream transport. The
route lists are empty. A second loopback DNS server returns either 600-second
or zero-TTL A/AAAA records. With zero TTL, every request reaches that upstream.
This fixture does not use an external network or encrypted upstream protocol.

| Routed path | Before | After | B/op before → after | Allocations before → after |
| --- | ---: | ---: | ---: | ---: |
| Warm upstream cache | 33.771 us | 28.634 us | 1,970 → 1,890 | 51 → 48 |
| Zero-TTL upstream miss | 124.014 us | 120.404 us | 8,651 → 8,459 | 204 → 189 |

The zero-TTL fixture records **three upstream questions per inbound request**:
the existing route-address lookup asks for A and AAAA, then the original A
question is resolved again. This behavior is preserved here. Avoiding that
pre-resolution when no IP-based routing can use it is a separate optimization
candidate; it needs routing-policy coverage before changing those semantics.
The small cold-path timing difference is not a claim about WAN performance.

## Client, index and memory costs

| Operation | Before | After | B/op before → after | Allocations before → after |
| --- | ---: | ---: | ---: | ---: |
| Cached client Raw, without encoding | 270.1 ns | 198.1 ns | 304 → 288 | 5 → 4 |
| Client cache key, HTTPS | 87.65 ns | 30.86 ns | 40 → 24 | 2 → 1 |
| UDP correlation key, HTTPS | 116.5 ns | 47.26 ns | 40 → 24 | 2 → 1 |

Direct rule lookup plus NXDOMAIN message construction takes 216.8 ns for 10
rules, 228.0 ns for 1,000 and 244.1 ns for 10,000; all allocate 304 B in three
allocations. These are resolver microbenchmarks, not full DNS requests.

Building 1,000/10,000 negative-response rules takes 0.310/3.265 ms and allocates
349 KB/3.27 MB. After GC, the additional live index retains approximately
293/284 bytes per rule: about **2.84 MB for 10,000 rules**, excluding the already
allocated input configuration and its domain strings. Configurations containing
answer records retain their parsed records as well. Replies clone these records
so caller mutation cannot change active rules. Construction work is outside the
query path. `B/op` and allocation-space profiles describe allocation traffic,
not retained RSS or a long-running production memory bound.

## Optimizations and profiles

- Optional `LocalDNSResponder` replies are matched before routing context and
  timeout/timer allocation. The DNS server depends on a small netapi interface;
  the response module has no FakeIP dependency.
- Unpack borrows the query buffer for the duration of processing. Encoding uses
  an exclusively owned pooled wire buffer, returned after synchronous write-back.
- Client/UDP key construction writes decimal numbers into stack buffers and
  allocates only the final key string.
- Cached `Raw` responses drop the wire buffer shared by the library's shallow
  `Msg.Copy`. Concurrent callers can encode different IDs independently. A race
  regression reproduces the original shared-buffer writes and passes after the
  repair. The response module also preserves HTTPS when cloning its embedded
  SVCB data.
- Empty configurations publish a nil snapshot and forward lookups directly.

The final five-second custom-AAAA datagram CPU profile attributes 10.9% of flat
samples to futex operations and 3.8% to `runtime.selectgo`; scheduling and GC
remain visible. DNS name packing accounts for 1.7% flat/4.7% cumulative. The
allocation-space profile attributes 36.2% flat to message creation and 24.6% to
packet creation; AAAA record cloning accounts for 8.1%. Request contexts and
timeouts no longer appear among the material allocations for a local hit.

Further pooling of message/packet objects would require careful ownership across
callbacks, cached records and async queue consumers. This change keeps those
objects independent rather than introducing a shared mutable lifetime to save
the remaining allocations. CPU profile percentages are sampled process costs,
including workers and GC, not a per-query CPU utilization guarantee.

## Reproduction

```sh
go test ./pkg/net/dns/response -run '^$' -bench BenchmarkResponseRules -benchmem -benchtime=500ms -count=3
go test ./pkg/net/dns/resolver -run '^$' -bench 'Benchmark(ClientRawCached|DNSCacheKeys)$' -benchmem -count=5
go test ./pkg/resolver -run '^$' -bench 'BenchmarkDNS(DatagramPipeline|RoutedUDPPipeline)$' -benchmem -benchtime=500ms -count=5
go test ./pkg/resolver -run '^$' -bench '^BenchmarkDNSUDPPipeline$' -benchmem -benchtime=500ms -count=3
go test ./pkg/resolver -run '^$' -bench '^BenchmarkDNSDatagramPipeline/aaaa/' -benchtime=5s -cpuprofile=/tmp/dns-cpu.pprof -memprofile=/tmp/dns-mem.pprof -o /tmp/dns-resolver.test
go tool pprof -top /tmp/dns-resolver.test /tmp/dns-cpu.pprof
go tool pprof -top -alloc_space /tmp/dns-resolver.test /tmp/dns-mem.pprof
```

To reproduce the source-only baseline without changing the worktree:

```sh
task_dns_bench_dir=$(mktemp -d)
python3 - "$task_dns_bench_dir" <<'PY'
import json, pathlib, subprocess, sys
root, output = pathlib.Path.cwd(), pathlib.Path(sys.argv[1])
files = ['pkg/net/dns/resolver/dns.go', 'pkg/net/dns/resolver/udp.go', 'pkg/net/dns/server/server.go']
replacements = {}
for index, source in enumerate(files):
    target = output / f'baseline-{index}.go'
    target.write_bytes(subprocess.check_output(['git', 'show', f'8bb71abd:{source}']))
    replacements[str(root / source)] = str(target)
(output / 'overlay.json').write_text(json.dumps({'Replace': replacements}))
PY
go test -overlay="$task_dns_bench_dir/overlay.json" ./pkg/resolver -run '^$' -bench 'BenchmarkDNS(DatagramPipeline|RoutedUDPPipeline)$' -benchmem -benchtime=500ms -count=5
```

Run comparisons sequentially. Kernel loopback timing, empty routing lists and a
zero-TTL local upstream do not establish real encrypted/WAN DNS performance,
parallel saturation capacity, or long-tail latency under mixed workloads.

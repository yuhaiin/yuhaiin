# Lightweight TCP/IP stack measurements

Status: experimental; these measurements do not justify replacing either legacy
stack. All numbers below are measured locally, not imported from reference projects.

See the [BBR v3 and ownership report](lightweight-bbr-v3.md) for current code
and measurements. The [transport checkpoint](lightweight-optimization.md) and
the full original matrix below are historical and predate that work.

## Environment and reproducibility

- Date: 2026-10-16, Asia/Taipei.
- AMD Ryzen 5 5600G, 6 cores / 12 threads; boost disabled on this host.
- Linux 7.2.6-zen2-1-zen x86_64, Go 1.27.2-X:nodwarf5.
- Native TUN comparison: GOMAXPROCS=4; MTU 1280/1500/9000;
  IFF_TUN|IFF_NO_PI; one queue; txqueuelen=10000; no VNET/GSO/GRO/offload.
- 90 cases, three fresh process/network-namespace samples per case. Each sample
  uses Go's adaptive B.Loop for 200ms. Each operation transfers 64KiB per active
  flow and validates content; flows=1/8/100, upload and download.
- Client is Linux TCP in the same benchmark process. CPU-s/GB includes client,
  stack, system calls, completion markers and workload coordination. It is not
  stack-only CPU or VPN encrypted throughput. Kernel CPU outside the process
  is not fully represented by process rusage.
- All implementations use the same pre-opened, ordinary packet TUN. gVisor uses
  its production channel endpoint, CUBIC/SACK and gonet; tun2socket uses its
  production NAT/Accept path. The full application routing/relay is excluded
  equally. This does not benchmark gVisor's fdbased/offload alternatives.

Commands (run from the repository root):

```sh
python3 scripts/benchmarks/lightweight.py --samples 3 --benchtime 200ms \
  --output docs/benchmarks/lightweight-results/tun.txt
# Short reproduction: add --quick (MTU 1500, one flow).
GOMAXPROCS=4 go test ./pkg/net/proxy/tun/lightweight -run '^$' \
  -bench '^Benchmark(UDP|ImpairedTCP)$' -benchtime=1s -count=3 -benchmem
CGO_ENABLED=1 go test -race ./pkg/net/proxy/tun/...
go test ./pkg/net/proxy/tun/lightweight/... -run '^$' -bench . -benchtime=1x -benchmem
go test -race -c -tags lightweight_kernel -o /tmp/lightweight-kernel.test \
  ./pkg/net/proxy/tun/lightweight
unshare -Urn /tmp/lightweight-kernel.test -test.run '^TestLinuxKernel' -test.v
```

The kernel suite fails if explicitly selected without TUN/network privileges;
it never reports a missing capability as a passing interoperability test.
The runner captures every sample and computes medians, rejecting failed samples.
200ms is a short local comparison: high-flow P95/P99 often have only a few dozen
observations, so treat tail percentiles as descriptive, not stable service SLOs.
The current harness uses the lower empirical order statistic floor((n-1)*p);
with very few iterations these percentiles cannot describe rare latency tails.

Log files normalize trailing whitespace only; numerical values are unchanged.

Raw records: [TUN samples](lightweight-results/tun.txt),
[all samples and medians](lightweight-results/tun.json),
[memory/link scenarios](lightweight-results/memory-links.txt).

## MTU 1500 summary

MB/s uses decimal megabytes. Latency is one completed batch across all active
flows, in microseconds. B/op and allocations/op refer to the entire batch.
The live-looking `heap-live-B` raw metric is actually instantaneous HeapAlloc
without a forced GC; it includes uncollected garbage and must not be treated as
retained live heap. Forced-GC heap profile evidence is described separately.
RSS is the whole benchmark process, not per-connection heap.

| Stack | Flows | Direction | MB/s | CPU s/GB | B/op | Allocs/op | P95 us | P99 us | RSS MiB |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| gvisor | 1 | upload | 331.69 | 5.183 | 671 | 26 | 239.3 | 272.6 | 23.1 |
| gvisor | 1 | download | 227.11 | 9.309 | 1156 | 53 | 384.8 | 419.9 | 21.1 |
| gvisor | 100 | upload | 441.24 | 5.315 | 158346 | 3330 | 15758.0 | 15758.0 | 37.7 |
| gvisor | 100 | download | 204.96 | 11.490 | 2043438 | 8394 | 34495.0 | 34495.0 | 47.9 |
| tun2socket | 1 | upload | 211.77 | 7.459 | 3286 | 136 | 345.6 | 396.6 | 22.8 |
| tun2socket | 1 | download | 257.86 | 4.033 | 2384 | 96 | 272.4 | 311.2 | 22.6 |
| tun2socket | 100 | upload | 191.68 | 8.788 | 638697 | 14554 | 33519.0 | 33519.0 | 37.1 |
| tun2socket | 100 | download | 203.69 | 8.431 | 645205 | 13915 | 31879.0 | 31879.0 | 35.0 |
| reno | 1 | upload | 353.18 | 4.910 | 81003 | 186 | 278.1 | 387.3 | 22.3 |
| reno | 1 | download | 313.70 | 7.220 | 218826 | 225 | 314.9 | 393.3 | 22.0 |
| reno | 100 | upload | 247.37 | 4.641 | 8778482 | 19031 | 15378.0 | 15378.0 | 49.3 |
| reno | 100 | download | 346.74 | 9.330 | 34084086 | 37393 | 20567.0 | 20567.0 | 59.1 |
| cubic | 1 | upload | 356.37 | 4.880 | 81003 | 186 | 276.9 | 373.1 | 21.8 |
| cubic | 1 | download | 316.68 | 7.058 | 218800 | 224 | 312.7 | 395.9 | 21.9 |
| cubic | 100 | upload | 251.66 | 4.635 | 8156144 | 18974 | 15074.0 | 15074.0 | 49.3 |
| cubic | 100 | download | 346.87 | 9.347 | 34337177 | 37312 | 20044.0 | 20044.0 | 60.4 |
| bbr | 1 | upload | 346.80 | 4.983 | 81038 | 186 | 280.7 | 385.9 | 22.2 |
| bbr | 1 | download | 304.50 | 7.232 | 218728 | 224 | 330.6 | 401.0 | 22.1 |
| bbr | 100 | upload | 453.92 | 4.679 | 8180025 | 18993 | 15449.0 | 15449.0 | 49.3 |
| bbr | 100 | download | 185.53 | 9.534 | 23230776 | 29465 | 50210.0 | 50210.0 | 54.8 |

The new stack is not uniformly faster. At 100-flow upload, CUBIC measured
251.66 MB/s versus gVisor's 441.24 MB/s. Single-flow download used about 219KB
allocated per operation versus gVisor's 1.2KB. Packet construction, receive
copies and retransmission ownership are currently allocation-heavy. BBR's
local results differ from CUBIC, but this short low-RTT workload cannot establish
BBR's advantage on a congested remote tunnel. tun2socket's single-flow download
CPU cost is lower than lightweight's in this setup.

## Full native TUN throughput matrix

Every value is the median of three independent processes. All sample counters,
latencies and memory metrics remain in the JSON, including retransmissions and
drops. Shutdown-related packets can contribute to the counters because these
are sampled after workload cleanup; the counters are not normalized per op.

| Stack | MTU | Flows | Upload MB/s | Download MB/s |
| --- | ---: | ---: | ---: | ---: |
| gvisor | 1280 | 1 | 295.74 | 188.97 |
| gvisor | 1280 | 8 | 375.03 | 195.97 |
| gvisor | 1280 | 100 | 380.83 | 174.67 |
| gvisor | 1500 | 1 | 331.69 | 227.11 |
| gvisor | 1500 | 8 | 422.02 | 247.60 |
| gvisor | 1500 | 100 | 441.24 | 204.96 |
| gvisor | 9000 | 1 | 870.31 | 782.78 |
| gvisor | 9000 | 8 | 1531.84 | 979.21 |
| gvisor | 9000 | 100 | 1622.03 | 935.87 |
| tun2socket | 1280 | 1 | 172.44 | 227.71 |
| tun2socket | 1280 | 8 | 184.88 | 189.71 |
| tun2socket | 1280 | 100 | 165.02 | 173.64 |
| tun2socket | 1500 | 1 | 211.77 | 257.86 |
| tun2socket | 1500 | 8 | 218.41 | 223.45 |
| tun2socket | 1500 | 100 | 191.68 | 203.69 |
| tun2socket | 9000 | 1 | 732.99 | 660.29 |
| tun2socket | 9000 | 8 | 870.49 | 932.01 |
| tun2socket | 9000 | 100 | 885.90 | 888.82 |
| reno | 1280 | 1 | 322.88 | 300.04 |
| reno | 1280 | 8 | 404.48 | 321.08 |
| reno | 1280 | 100 | 407.61 | 284.68 |
| reno | 1500 | 1 | 353.18 | 313.70 |
| reno | 1500 | 8 | 448.57 | 378.24 |
| reno | 1500 | 100 | 247.37 | 346.74 |
| reno | 9000 | 1 | 657.66 | 541.72 |
| reno | 9000 | 8 | 1039.90 | 1193.18 |
| reno | 9000 | 100 | 1130.31 | 1333.74 |
| cubic | 1280 | 1 | 318.35 | 289.79 |
| cubic | 1280 | 8 | 404.64 | 326.48 |
| cubic | 1280 | 100 | 413.42 | 291.71 |
| cubic | 1500 | 1 | 356.37 | 316.68 |
| cubic | 1500 | 8 | 450.70 | 381.61 |
| cubic | 1500 | 100 | 251.66 | 346.87 |
| cubic | 9000 | 1 | 660.50 | 540.71 |
| cubic | 9000 | 8 | 1034.55 | 1192.68 |
| cubic | 9000 | 100 | 1113.35 | 1337.67 |
| bbr | 1280 | 1 | 318.17 | 1.48 |
| bbr | 1280 | 8 | 397.72 | 90.64 |
| bbr | 1280 | 100 | 222.46 | 148.74 |
| bbr | 1500 | 1 | 346.80 | 304.50 |
| bbr | 1500 | 8 | 445.26 | 94.23 |
| bbr | 1500 | 100 | 453.92 | 185.53 |
| bbr | 9000 | 1 | 648.92 | 489.03 |
| bbr | 9000 | 8 | 1024.36 | 1110.24 |
| bbr | 9000 | 100 | 1108.89 | 1217.07 |

## Other workloads and profiling

The portable benchmark matrix covers three controllers, MTU 1280/1500/9000,
1/8/100 flows, 64-byte/64KiB payloads and upload/download. The UDP matrix covers
64/512/1200 bytes and 1/100 source sockets, reporting packets/s and allocation
cost. IdleThousand creates 1000 connections per endpoint, records accounted
bytes/connection and goroutines, then closes both stacks. Accounting is not
an independent RSS/live-heap comparison against the legacy stacks; that
specific idle-memory baseline remains outstanding.

ImpairedTCP uses gVisor as the independent peer, with a fixed random seed,
bounded queues and two shared link workers (no timer/goroutine per packet).
Scenarios are RTT 1ms/10ms, 50ms with 0.1% configured loss and jitter, 100ms with
1% configured loss and jitter, and 100ms/10Mbps with a 32-packet queue.
Configured loss is a probability, not a guarantee that a short sample drops a
packet: inspect link-drops. Jitter can trigger spurious fast retransmits even
when no packet is dropped. Memory-link results include both endpoint stacks,
link copies and workers. They are not directly comparable with the native TUN
baselines. They do not establish long-duration bandwidth fairness or a full
legacy-stack comparison on every impaired scenario.

The CPU/heap profile was collected separately, with GOMAXPROCS=4, on a 1-second
in-memory CUBIC download at MTU 1500, one flow, 64KiB. It includes both endpoints
and the memory-link copying, so it is diagnostic rather than a stack-only
production cost estimate.

```sh
go test -c -o /tmp/lightweight-profile.test ./pkg/net/proxy/tun/lightweight
GOMAXPROCS=4 /tmp/lightweight-profile.test -test.run '^$' \
  -test.bench '^BenchmarkTCP$/^cubic$/^mtu=1500$/^flows=1$/^payload=65536$/^download$' \
  -test.benchtime=1s -test.cpuprofile=/tmp/lightweight-cpu.pprof \
  -test.memprofile=/tmp/lightweight-heap.pprof
go tool pprof -top /tmp/lightweight-profile.test /tmp/lightweight-cpu.pprof
go tool pprof -top -sample_index=alloc_space /tmp/lightweight-profile.test /tmp/lightweight-heap.pprof
go tool pprof -top -sample_index=inuse_space /tmp/lightweight-profile.test /tmp/lightweight-heap.pprof
```

[CPU top](lightweight-results/cpu-top.txt) attributes about 12.9% flat CPU to
checksum summation, followed by copying, channel selection and runtime locking.
[Allocated heap](lightweight-results/heap-alloc-top.txt) attributes most bytes to
TCP Write/receive, the memory peer's bytes.Clone, IP construction and TCP output.
These explain why bounded ownership currently costs substantially more allocated
bytes than gVisor's pooled path. [Post-GC live samples](lightweight-results/heap-live-top.txt)
show runtime allocations after teardown and no attributed retained core buffers;
the default sampled heap profile is not an exact byte census. The explicit
accounting and goleak tests provide the independent reclamation assertions.

## Validation and gaps

Passed locally:

- Complete TUN package race tests with CGO_ENABLED=1; focused CI linter v2.14.0
  reports zero issues; focused vet and contract/inbound tests.
- gVisor TCP peers: three algorithms, both families, both directions,
  packet loss/duplication/reordering, payload/order/half-close validation.
- Linux kernel peers in isolated user/network namespaces, also under race:
  TCP in both directions/families for all controllers; UDP fragmentation and
  ICMP echo; connected UDP error association is included in the kernel suite.
- 1000 connections reclaimed with goleak; blocked IO/Close, queue admission,
  window scaling/wrap, SACK/fast recovery, Karn, RST/TIME-WAIT and actual pacing.
- Parser fuzz campaigns and the complete portable benchmark smoke matrix.
- Core builds for Linux 386/arm64/mipsle, Darwin arm64, Windows amd64,
  Android arm64 and iOS arm64. Whole TUN package builds for Darwin, Windows, Android and iOS. Linux release make target also builds.

Repository-wide go vet, go fix, lint and go test encounter the existing missing
`pkg/net/netlink/tcplife` import in `pkg/net/netlink/tcplife/test/test.go:8`.
The full test run otherwise completes, but is a failure overall. This change
does not repair that unrelated package or claim a clean full-repository gate.
Focused go fix modernized local-address membership to slices.Contains; a second
focused pass is checked for idempotence in the validation transcript. The full
command is blocked by the unrelated missing import.

Unverified: real macOS/Windows/mobile runtime behavior, L2/ARP/ND, Linux offload
and multiqueue acceleration, exhaustive TCP conformance/fault combinations,
full sustained impairment/fairness comparisons and independent legacy idle
live-heap/RSS baselines. Offload results are N/A, not a zero or an inferred gain.
Future removal of a legacy implementation requires resolving these gaps,
production traffic trials and measured allocation/performance improvements.

Failed development records are retained rather than folded into successful
medians: the initial 500-packet TUN queue run, queue-admission failures and a
lost output-wakeup race. The queue setting is now identical for all baselines;
TCP capacity admission and readiness/heap locking were corrected, and all 270
final native samples passed. The longer impairment run also exposed partial-ACK
recovery after RTO; that failure and its corrected rerun are retained separately.
A separate validation-time memory-link run is
retained but was run alongside checks; use the later dedicated run for timing.

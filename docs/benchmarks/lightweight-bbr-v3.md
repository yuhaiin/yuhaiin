# BBR v3, recovery and packet ownership

This report follows the historical [transport checkpoint](lightweight-optimization.md).
The stack remains opt-in; neither legacy stack nor default selection is replaced.
Raw measurements, including unsuccessful development runs, are in
[lightweight-results/bbr-v3](lightweight-results/bbr-v3).

## Controller and transport changes

`bbr` now selects BBR v3 only. The reference is Google's latest dated v3 branch
verified on 2026-10-16, `bbr-v3-2026-09-16-01`, commit
[674859761ded9f32690c7bdaf22ef585531452ed](https://github.com/google/bbr/blob/674859761ded9f32690c7bdaf22ef585531452ed/net/ipv4/tcp_bbr3.c).
The actual v3 file is `tcp_bbr3.c`; `tcp_bbr.c` in that branch is not v3.
[Attribution and BSD-3-Clause terms](../../licenses/bbr-v3.md) are embedded in
the existing binary license catalog as well as distributed in source.

The model includes STARTUP/DRAIN, PROBE_BW's UP/DOWN/CRUISE/REFILL phases,
round-based upper/lower bandwidth and inflight bounds, loss-aware probe
feedback, randomized and Reno-conscious probe timing, ACK aggregation,
min-RTT aging and PROBE_RTT. Fixed-point gains and thresholds follow that
reference. Byte units replace Linux's packet units. Quantization uses the
actual sender's 1ms pacing credit and 64-packet pump bound; no fictitious TSO
budget or benchmark-specific pacing multiplier is added. Model snapshots expose
version, phase, bandwidth/inflight bounds and round information.

The transport now supplies unique SACK delivery, loss since the previous ACK,
per-transmission delivery/loss/flight snapshots, persistent app-limited bubbles,
sub-MSS cwnd limitation and intentional PROBE_RTT limiting. ACK sampling copies
metadata before a descriptor can be recycled. Retransmission rate samples
remain usable; Karn suppresses ambiguous RTT samples. Linux bit-for-bit
behavior, ECN and live DSACK-proven spurious-loss undo are not claimed.

Reno and CUBIC independently use [RFC 9406 HyStart++](https://www.rfc-editor.org/rfc/rfc9406.html):
sequence-based rounds, eight valid RTT samples, 4–16ms delay threshold,
quarter-rate Conservative Slow Start, five CSS rounds and recovery from a
spurious delay exit. BBR uses its own STARTUP. Tests cover RTT sample validity,
sequence wrap, CSS persistence/reversion and loss/timeout reset.

SACK-based loss detection removes lost bytes from the pipe and can repair
multiple gaps before an RTO. Retransmission restores flight once. RTO preserves
useful SACK evidence; a suspected SACK reneging event gets a short confirmation
interval so reordered ACKs cannot cause immediate spurious repairs. A PMTU
replacement retains its sequence and sampling history, is explicitly eligible
for resend, and needs evidence beyond its retransmission boundary before it
can be marked lost again. Controller MSS changes preserve the byte model.

## Memory findings

A 2s CPU/allocation profile of CUBIC, MTU 1500, 100 download flows found about
70% of allocated bytes in per-MSS send descriptors and packet buffer misses.
Another major source was unrelated ACKs repeatedly waking a reader waiting for
data, recreating notification channels and deadline timers.

Send descriptors now share the bounded cache with owned payloads. Clearing a
descriptor precedes publishing either it or its payload for another connection.
Partial ACKs retain the immutable backing allocation; PMTU resegmentation reuses
the original descriptor for its first piece. Output waiters embed queue links,
and data/ACK progress notify separate read/write waiters. Close and state changes
still interrupt both. Native device writes respect an accepted packet count even when accompanied
by a trailing error, preventing a retry of an already accepted datagram. The
fixed connection metadata charge now covers retained
small queue arrays and built-in controller storage; reflection tests guard it.
An emptied reordering array is released.

All cached bytes remain in MemoryBytes. The shared cache is bounded by the
smaller of 10MiB and MemoryLimit/8, each payload class and descriptor queue by
4096 entries. Idle expiry releases it after 2–4s without a permanent wakeup.
Pressure can evict both payload and descriptor entries. This is not an exact
RSS cap: bounded channel arrays, runtime/GC, stacks and kernel sockets remain
outside payload accounting.

Exploratory 2s runs (one process each, diagnostic rather than final medians):

| CUBIC 100 downloads, MTU 1500 | MB/s | bytes/batch | allocations/batch | live heap MiB | peak RSS MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Before descriptor/notification work | 417.90 | 2,827,135 | 15,507 | 15.80 | 57.68 |
| Larger size-class count | 396.06 | 1,851,267 | 14,703 | 15.66 | 57.04 |
| Descriptor reuse | 411.37 | 1,246,619 | 9,340 | 15.93 | 57.17 |
| Separate notifications / embedded waiter links, 8MiB cache | 421.94 | 540,453 | 882 | 16.02 | 55.00 |
| 4MiB cache experiment, rejected | 431.35 | 4,937,639 | 4,346 | 12.15 | 55.14 |
| 10MiB cache, selected | 431.83 | 175,619 | 772 | 16.69 | 46.73 |
| gVisor, same final harness | 248.15 | 251,407 | 5,563 | 17.24 | 45.64 |

A smaller cache reduced live heap but increased churn and did not improve the
peak. The selected cap holds the measured roughly 9MiB working set. This
single-run evidence does not establish a universal RSS advantage: gVisor's peak
was still lower. CPU profiles include Linux TCP client, checksums and syscalls;
end-of-process heap profiles after Close do not represent live traffic memory.

The final 2s diagnostic profile is retained as `cpu-final.pprof` and
`alloc-final.pprof`. CPU samples are dominated by syscalls (56.1%), checksum
summation (9.9%) and copies (3.4%). Total sampled allocation fell from roughly
429MiB before the ownership/notification work to 43MiB in this profiled run;
these totals include setup, profiling and cleanup and are not bytes/batch.
Remaining allocation is chiefly descriptor/payload cache misses and workload
buffers. Both allocation profiles and their benchmark logs are retained.
End-of-process in-use profiles are taken after Close, so live traffic memory
continues to use the separate pre-cleanup GC measurement in the matrix.

## Shared bottleneck qualification

All senders share one bidirectional serialization queue and one independent
gVisor receiver. Propagation packets do not occupy the bottleneck queue. Data
content is validated continuously. Two BBR v3 senders and one CUBIC sender run
through 4s + 4 RTTs of warmup and three 10s measurement phases. Each flow must
continue to deliver in every phase. The dynamic profile changes 10→5→10Mbps.

Loss profiles also run CUBIC-only and BBR-only controls. Raw mixed Jain fairness
is always reported. A loss-based sender can be below its nominal equal share
even alone, so the additional normalized score divides each mixed goodput by
that algorithm's measured standalone goodput. It is a relative coexistence
measure, not a claim of equal absolute rates or general Internet fairness.

For explicit local performance qualification, `LIGHTWEIGHT_NETWORK_QUALIFY=1`
also checks intra-BBR Jain >=0.8; raw mixed Jain >=0.8 on no-loss profiles;
standalone-normalized mixed Jain >=0.8 on loss profiles; BBR >=10% of capacity;
CUBIC >=1/N of min(standalone rate, nominal 1/N share); total-trial payload
utilization >=50%. Warmup bytes and capacity are both included in utilization,
avoiding apparent >100% from data queued before the measurement interval.
These performance thresholds are not enabled in CI. CI checks protocol data,
continued per-phase progress, cleanup/races and resource bounds, and retains
metrics without enforcing host-dependent throughput percentages.

The retained early failures exposed sub-MSS cwnd-limited detection, serial hole
recovery and a queue model that incorrectly counted propagation as occupancy.
Short coexistence runs were also insufficient for several randomized v3 probe
cycles. Long trials and standalone controls replaced those preliminary tests;
earlier raw failures remain alongside the successful records.

## Reproduce

```sh
CGO_ENABLED=1 go test -race ./pkg/net/proxy/tun/...
LIGHTWEIGHT_NETWORK_QUALIFY=1 CGO_ENABLED=1 go test -race \
  -tags lightweight_qualification ./pkg/net/proxy/tun/lightweight \
  -run '^TestBBR(SharedBottleneck|BandwidthChanges)$' -count=1 -v -timeout=600s
CGO_ENABLED=1 go test -race -c -tags lightweight_kernel \
  -o /tmp/lightweight-kernel.test ./pkg/net/proxy/tun/lightweight
unshare -Urn /tmp/lightweight-kernel.test -test.run '^TestLinuxKernel' -test.v -test.timeout=90s

go test -c -tags lightweight_kernel -o /tmp/lightweight-bench.test ./pkg/net/proxy/tun/lightweight
python3 scripts/benchmarks/lightweight.py --binary /tmp/lightweight-bench.test \
  --samples 3 --benchtime 500ms --output /tmp/native-current.txt
python3 scripts/benchmarks/lightweight.py --binary /tmp/lightweight-bench.test \
  --idle --stacks gvisor tun2socket reno cubic bbr --samples 3 --output /tmp/idle-current.txt
```

All native comparisons use GOMAXPROCS=4, Linux TCP in the same process,
independent fresh network namespaces/processes, no VNET/offload and the same
64KiB-per-flow workload. A batch is one complete payload on every flow; bytes
and allocations per batch therefore scale with flow count. The runner retains
every sample, environment and binary SHA256. CPU excludes setup/GC/cleanup;
live heap is sampled after GC before socket cleanup; peak RSS is ru_maxrss.
Kernel socket RAM is excluded, particularly relevant to tun2socket. These local
no-offload results do not predict encrypted remote-tunnel throughput.

## Protocol evidence and remaining limits

Both gVisor and Linux peers exercise IPv4/IPv6 and all three controllers.
Continuous Linux PMTU tests transfer and validate a full payload plus FIN while
a simulated router changes MTU 4000→2000→1280. All six family/controller cases
must exercise all changes and finish without falsely classified network loss.
Wire tests additionally cover multiple decreases, sequence wrap, stale ACKs,
re-lost replacements, duplicate SACK delivery, ACK reordering and true reneging.

Portable core and adapter compilation is distinct from runtime validation.
macOS/Windows/mobile runtime qualification, ECN/timestamps/PAWS, UDP destination
PMTU caching and offload/multiqueue remain outside this opt-in implementation's
verified boundary. Broader hostile-network/conformance and fairness studies
remain necessary before retiring either legacy stack.

## Qualification results

The explicit-threshold run completed in 280.3s with all profiles passing. This
run includes the ownership pool, reader/writer notifications and PMTU fixes;
subsequent queue changes reclaim metadata and clear stale backing references.
The final CI additionally exercises the current source's sustained per-phase
progress without host-dependent percentage gates.

| Profile | Raw mixed Jain | Intra-BBR Jain | Normalized mixed Jain | Payload utilization |
| --- | ---: | ---: | ---: | ---: |
| 50ms, 10Mbps, queue 32 | 0.966 | 0.994 | n/a | 96.0% |
| 200ms, 0.1% loss, 10Mbps, queue 64 | 0.880 | 0.966 | 0.974 | 92.8% |
| 100ms, 1% loss, 10Mbps, queue 64 | 0.853 | 0.984 | 0.878 | 84.0% |
| 100ms, 10→5→10Mbps, queue 32 | 0.966 | 1.000 | n/a | 92.8% |

Raw records include every phase, standalone controls, loss counters and model
snapshots. These results apply to this model/reference peer and are not a
proof of fairness across other bottlenecks or competing implementations.

## Validation record

- All TUN packages plus licenses under `-race`: pass, including 1000-connection
  reclaim, I/O transient/close, FIFO capacity and buffer lifetime tests.
- Real Linux TUN kernel suite under race: pass; all three controllers and both
  families, including continuous PMTU changes with full payload/FIN checks.
- Ordinary benchmark smoke (`-bench . -benchtime=1x`): pass.
- Linux amd64/arm64/386/mipsle, Darwin arm64, Windows amd64, Android arm64 and
  iOS arm64 core **and adapter** builds: pass. Linux 386 protocol tests also pass.
- Workflow-pinned golangci-lint 2.14.0: zero issues; actionlint: pass.
- Production main build with repository release tags, CGO=0, GOAMD64=v3: pass.
- Raw `go test ./...`, `go vet ./...` and `go fix ./...` encounter a pre-existing
  ignored local diagnostic file, `pkg/net/netlink/tcplife/test/test.go`, importing
  a nonexistent package. It is not tracked in Git and was left untouched.
  A temporary Go overlay deleting only that file for package resolution lets
  full-repository vet/tests/fix checks run against the actual tracked sources.
  Those pass. `go fix` adapted one reverse loop to `slices.Backward`; the final
  `go fix -diff` check produces no changes. No diagnostic file was deleted.

A cache-pressure regression also verifies that returning only a send
descriptor wakes output while its shared payload remains live. Such a return
creates evictable budget even when no packet-buffer reference reaches zero.
The regression failed before the capacity notification was added and passes
under race afterward. A separate final matrix includes that notification.

The native matrix preceding the final stale-reference clearing is retained as
`native-before-reference-clear.*`; it completed all 270 samples, resuming 119
completed samples after the close-log parsing repair. The matrix before the descriptor-capacity notification is retained as
`native-pre-metadata-wakeup.*`. The final matrix is a separate fresh run of
the final source. No older measurement is silently replaced.
Final idle and native sampling use the same binary. The earlier
unmatched Reno filter is retained as `idle-filter-mismatch.txt` and
was repaired by adding all controllers to the idle benchmark.

## Final native medians

The final source completed 270 fresh-process samples over all 90 workload
cases (three per case), 500ms per sample, on 2026-10-17. Both the initial full
matrix and final full matrix remain available; every median below uses only
`native-final.json`. No offload is enabled.

| MTU | Flows | Direction | gVisor MB/s | tun2socket MB/s | Reno MB/s | CUBIC MB/s | BBR v3 MB/s |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 1280 | 1 | upload | 291.36 | 172.61 | 343.89 | 342.04 | 342.24 |
| 1280 | 1 | download | 187.54 | 226.65 | 298.94 | 305.00 | 301.37 |
| 1280 | 8 | upload | 366.60 | 186.04 | 434.47 | 431.32 | 434.34 |
| 1280 | 8 | download | 203.98 | 183.71 | 349.80 | 344.93 | 340.80 |
| 1280 | 100 | upload | 371.45 | 178.93 | 432.74 | 435.17 | 439.87 |
| 1280 | 100 | download | 188.81 | 180.67 | 323.42 | 323.29 | 332.91 |
| 1500 | 1 | upload | 330.13 | 210.18 | 383.12 | 387.38 | 383.59 |
| 1500 | 1 | download | 227.05 | 256.55 | 333.74 | 339.87 | 334.28 |
| 1500 | 8 | upload | 420.49 | 218.83 | 492.34 | 482.65 | 493.59 |
| 1500 | 8 | download | 254.63 | 226.84 | 430.35 | 428.24 | 430.70 |
| 1500 | 100 | upload | 442.47 | 211.02 | 487.86 | 493.55 | 495.42 |
| 1500 | 100 | download | 234.89 | 208.96 | 399.78 | 409.81 | 422.75 |
| 9000 | 1 | upload | 876.50 | 711.51 | 751.91 | 745.11 | 748.40 |
| 9000 | 1 | download | 766.16 | 643.41 | 748.49 | 749.82 | 741.32 |
| 9000 | 8 | upload | 1551.02 | 891.92 | 1219.37 | 1211.97 | 1185.94 |
| 9000 | 8 | download | 969.02 | 942.72 | 1467.29 | 1487.71 | 1528.82 |
| 9000 | 100 | upload | 1623.05 | 888.63 | 1290.03 | 1274.19 | 1283.03 |
| 9000 | 100 | download | 960.74 | 889.40 | 1572.24 | 1667.73 | 1624.14 |

MTU 1500 CPU/memory medians. Allocation and latency are per complete batch
of all flows; they are not independent packet latency.

| Stack | Flows/direction | CPU s/GB | bytes/batch | allocs/batch | live heap MiB | peak RSS MiB | P95/P99 ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| gvisor | 1/download | 9.299 | 869 | 53 | 1.00 | 25.15 | 0.41/0.43 |
| tun2socket | 1/download | 4.096 | 2,314 | 96 | 0.53 | 24.52 | 0.28/0.32 |
| reno | 1/download | 6.352 | 469 | 5 | 1.12 | 24.46 | 0.25/0.27 |
| cubic | 1/download | 6.157 | 465 | 5 | 1.12 | 24.16 | 0.25/0.27 |
| bbr | 1/download | 6.320 | 472 | 5 | 1.12 | 24.30 | 0.25/0.28 |
| gvisor | 100/upload | 5.210 | 236,566 | 3,286 | 8.45 | 35.49 | 16.82/17.30 |
| tun2socket | 100/upload | 8.058 | 528,169 | 13,984 | 6.97 | 34.80 | 45.44/45.44 |
| reno | 100/upload | 4.307 | 581,999 | 6,868 | 8.28 | 40.73 | 14.69/15.45 |
| cubic | 100/upload | 4.237 | 522,990 | 6,836 | 8.37 | 38.71 | 14.07/14.39 |
| bbr | 100/upload | 4.218 | 483,256 | 6,813 | 8.40 | 38.60 | 13.97/14.34 |
| gvisor | 100/download | 10.280 | 909,641 | 6,438 | 18.05 | 45.35 | 33.91/35.07 |
| tun2socket | 100/download | 8.202 | 333,932 | 13,850 | 6.98 | 32.88 | 44.98/44.98 |
| reno | 100/download | 7.922 | 532,113 | 1,049 | 16.62 | 40.74 | 19.70/20.03 |
| cubic | 100/download | 7.760 | 486,947 | 991 | 16.61 | 42.74 | 19.24/20.95 |
| bbr | 100/download | 8.140 | 501,667 | 1,010 | 16.73 | 42.94 | 18.50/19.46 |

BBR's MTU 1280 single-download median is 301.37 MB/s, versus
the original 1.48 MB/s. At MTU 1500, CUBIC 100-flow download is 409.81
versus 234.89 MB/s for gVisor, with 486,947 versus 909,641
bytes allocated per batch. These observations do not establish an across-the-board
memory advantage: upload allocation remains higher, as do single-flow live heap
and some RSS cases. The full raw medians retain every unfavorable result.

Retransmission/drop counters are cumulative from stack creation, including
startup; lightweight recorded one startup drop and zero retransmissions in these
trials. Short 500ms runs have few tail observations at 100 flows; their P99 is
not a stable long-duration tail estimate. Local no-offload results do not
predict encrypted remote-tunnel throughput.


### 1000 idle connections

| Stack | heap delta bytes/connection | added goroutines/connection | total idle heap MiB |
| --- | ---: | ---: | ---: |
| gvisor | 5084 | 0 | 5.35 |
| tun2socket | 1027 | 0 | 1.39 |
| reno | 1488 | 0 | 2.23 |
| cubic | 1585 | 0 | 2.33 |
| bbr | 1936 | 0 | 2.66 |

The idle delta subtracts a post-setup baseline and excludes kernel socket
memory. Raw records also include RSS and live heap after socket closure.
Protocol caches drain on Stack.Close; runtime caches may remain. Final idle and native
measurements use the same binary, verified by the SHA256 in each artifact.

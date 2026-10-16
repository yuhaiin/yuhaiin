# Transport optimization checkpoint

Status: work in progress on 2026-10-16. This checkpoint improves the transport
and records remaining regressions; it does not complete the acceptance matrix.
The current controller is still BBR v1. The requested final implementation must
replace it with BBR v3, with no v1/v2 selection, and add HyStart++ to Reno/CUBIC.

## Correctness and ownership

- PMTU repair keeps original send/RTT history and sequence space while explicitly
  scheduling every outstanding replacement. Replacements share immutable owned
  payload views. Tests transfer the complete flight through three successive MTU
  reductions for all controllers, verify caller-buffer independence, final ACKs,
  and reject ambiguous RTT samples. IPv6 and independent-peer PMTU stress remain.
- `bytesInFlight` is maintained on first transmission, cumulative/partial ACK,
  SACK, SACK reneging after RTO, PMTU repair and teardown. Duplicate SACKs cannot
  deduct bytes twice. Retransmission does not add another copy to the flight.
- Full output queues and insufficient packet memory do not wake queued flows.
  Waiters retain FIFO ordering; registration precedes the readiness check, and
  normal releases avoid the shared lock when no waiter exists.
- Packet output uses one IP/TCP allocation and a bounded stack-local option
  array. Bounded byte caches retain their full charged capacity in the global
  memory budget, evict on pressure, expire after 2-4 idle seconds, and stop their
  shared expiration job when empty. Cache admission is capped at the smaller of
  8 MiB and one eighth of the memory limit. Oversize datagrams are not cached.
- Writes copy at most 16 KiB once and create read-only MSS views. Partial ACKs
  retain the backing allocation until its last view is ACKed. Queues reuse head
  capacity and discard burst-sized metadata arrays when empty. Notification
  channels are allocated only when an operation actually waits.
- The adapter borrows zero-offset device output synchronously and uses the
  existing pool for offset copies. A device batch is drained before its pending
  error is returned. UDP forwarding transfers the allocation already owned by
  `ReceiveUDP` into `netapi.Packet`, removing the second clone.
- EINTR, EAGAIN, ENOBUFS and temporary device errors are retryable. Repeated
  failures back off with interruptible waits; Close interrupts retries. Read-side
  short-buffer drops do not stop the stack. Permanent errors still stop it.
- CodeQL alert 173 (`go/allocation-size-overflow`) referred to the old TCP
  allocation at `20+len(opts)+len(data)`. Payload/header limits are now checked
  explicitly before allocation arithmetic. Tests cover negative/MaxInt lengths,
  IPv4/IPv6 wire limits, oversize TCP output and a native 32-bit build/run. The
  hosted alert must be rechecked after pushing; local tests alone do not close it.

## Comparable measurements

`before` and `optimized` use the corrected harness: identical 64 KiB/flow
workload, MTU 1500, no offload, GOMAXPROCS=4, 500 ms, three separate processes and
network namespaces per case. Each batch validates content. CPU includes the
Linux clients and workload coordination, excluding setup/forced-GC/cleanup;
process accounting does not include all kernel/softirq costs. These are local
TUN results, not remote encrypted throughput.

Median throughput, decimal MB/s:

| Flows | Direction | Before CUBIC | Optimized CUBIC | gVisor, same rerun |
| ---: | --- | ---: | ---: | ---: |
| 1 | upload | 356.84 | 392.94 | 331.41 |
| 1 | download | 320.38 | 324.57 | 231.62 |
| 100 | upload | 453.97 | 503.19 | 440.47 |
| 100 | download | 358.58 | 392.65 | 240.33 |

Allocation is per completed batch. Live heap is measured after forced GC while
connections and workload buffers are still live. Peak RSS is whole-process
rusage, which includes live heap, transient garbage and runtime/OS overhead.

| Flows | Direction | CUBIC B/op before -> after | gVisor B/op | Live heap MiB CUBIC / gVisor | Peak RSS MiB CUBIC / gVisor |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 | upload | 80991 -> 4259 | 591 | 0.79 / 0.81 | 22.29 / 22.91 |
| 1 | download | 218861 -> 13218 | 870 | 0.84 / 1.00 | 22.40 / 22.72 |
| 100 | upload | 8208872 -> 598299 | 216958 | 7.98 / 8.55 | 36.70 / 33.27 |
| 100 | download | 31469628 -> 3009434 | 710306 | 14.61 / 18.02 | 51.02 / 43.45 |

The high-flow download still allocates substantially more than gVisor and has a
higher peak RSS. A larger reusable cache lowers allocation traffic but increases
retained heap. Descriptor reuse, in-order receive handling and cache sizing need
further measurement. No claim of uniform memory superiority is made.

1000 idle connections, same Linux clients, three independent process samples;
post-GC heap/RSS deltas from the stack's own pre-connection baseline:

| Stack | Heap bytes/connection | RSS bytes/connection | Added goroutines/connection |
| --- | ---: | ---: | ---: |
| gvisor | 5071 | 7770 | 0 |
| tun2socket | 1027 | 2503 | 0 |
| cubic | 1495 | 4510 | 0 |

Kernel socket memory is outside these process metrics, especially relevant to
tun2socket. Idle measurements do not establish retained RAM after heavy traffic.

## BBR diagnosis and remaining controller work

The rate regression test sends a continuous 146000 B/s flight. Before repair,
the sampled rate decays to 5763 B/s because the send-phase origin remains at the
beginning of the connection. The origin now advances with ACK delivery. A
second failing test showed that `queuedBytes < cwnd` labels paced backlog as
application-limited. Backlog is now distinguished from an empty write queue;
full app-limited bubble/rate/loss accounting will be completed with v3.

A separate error was restarting every pacing deadline from the late wake time.
Timer lateness permanently reduced the effective rate. Pacing now keeps at most
1 ms of earned credit, independently bounded by cwnd and the pump budget; idle
periods cannot accumulate unlimited credit. A regression checks both catch-up
and the burst bound. This applies to the TCP sender, regardless of BBR version.

The old MTU-1280 single-flow download can time out in a longer run; those failed
raw records are retained. The intermediate rate-only diagnostic reached
13.65 MB/s. Adding bounded pacing credit reached 151.51 MB/s in a separate
500 ms sample. These are diagnosis checkpoints using the old controller, not
BBR v3 results or final performance claims. `LIGHTWEIGHT_BBR_TRACE=1` enables
opt-in benchmark state logging; trace runs include logging overhead.

The final controller reference is Google's latest dated v3 branch:
[`bbr-v3-2026-09-16-01`, commit `674859761ded9f32690c7bdaf22ef585531452ed`](https://github.com/google/bbr/blob/674859761ded9f32690c7bdaf22ef585531452ed/net/ipv4/tcp_bbr3.c).
The file is `tcp_bbr3.c`; `tcp_bbr.c` on that branch is v1. The older `v3` branch
still uses `tcp_bbr.c`, so choosing a filename without verifying the version is
insufficient. The final port must cover upper/lower bandwidth and inflight
bounds, UP/DOWN/CRUISE/REFILL, STARTUP loss exit, ACK aggregation, ProbeRTT,
recovery and randomized Reno-coexistence probes. It must be tested under high
RTT, loss, rate limits, bandwidth changes and simultaneous competing flows.

Reno/CUBIC HyStart++ will follow [RFC 9406](https://www.rfc-editor.org/rfc/rfc9406.html),
including per-round minima, eight valid samples, bounded delay threshold,
conservative growth, spurious-exit recovery and the five-round CSS limit.
BBR v3 will retain its own STARTUP.

## Reproduce and inspect

```sh
python3 scripts/benchmarks/lightweight.py --stacks gvisor cubic \
  --mtus 1500 --flows 1 100 --samples 3 --benchtime 500ms \
  --output /tmp/optimized-tun.txt
python3 scripts/benchmarks/lightweight.py --idle --samples 3 \
  --output /tmp/idle-tun.txt
```

The harness-only baseline is commit `ed3e4ad3`; building that revision provides
the pre-optimization core with the corrected measurement harness.
Use `--binary` to preserve a specific before/after executable. New raw records
include its SHA-256. The runner streams the hash so its parent process does not
load the binary into RSS inherited across fork/exec. The p95/p99 estimator now
uses nearest rank, and tails remain descriptive with so few batch observations.
Historical baseline `heap-live-B` was instantaneous HeapAlloc; only this updated
harness forces GC before reporting that metric.

[Raw samples and medians](lightweight-results/optimization/) retain each stage:
`before`, `pool`, `queue`, `bulk`, `cache`, `optimized`, `idle`, and BBR diagnostics.
`bulk` overlapped an initial race run and is diagnostic only; final comparisons
use independently run `before` and `optimized`. BBR diagnostic timeout stacks
are failed evidence, not successful test output.

This checkpoint passed the full TUN race suite, independent Linux TCP/UDP/ICMP
race tests, workflow-pinned golangci-lint v2.14.0, focused go fix, Windows builds
and native 386 boundary tests. Full `go fix ./...` remains blocked by the
pre-existing missing `pkg/net/netlink/tcplife` package; it changed no core/adapter
source. The PR remains Draft pending BBR v3, HyStart++, the remaining resource
and performance work, and the original acceptance gaps.

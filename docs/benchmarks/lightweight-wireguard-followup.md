# WireGuard integration and upload/memory follow-up

This follows the merged lightweight stack in #544. The implementation baseline
is commit `8525676c`, which includes the WireGuard adapter but precedes the
receive, deadline, notification and cache optimizations below. The frontend
configuration and driver dropdown were merged separately in yuhaiin-react
#487/#488; the DNS reply address hotfix is on main as `85c24ddd`.

## Integration

WireGuard, AmneziaWG and MASQUE select `LightweightNetTun`, the remote tunnel
profile, and default CUBIC + HyStart++. OpenVPN, GlobalProtect, SoftEther, L2TP
and VPNKit continue constructing the original gVisor `NetTun`. Existing VPN
configuration contracts and legacy concrete socket wrappers remain available.

The new bridge acknowledges a synchronous borrowed packet only after copying
it into the reader's buffer. Closing interrupts unaccepted transfers and waits
for already accepted copies before releasing their memory. Prefix/suffix space,
engine offsets, packet counts, short buffers and duplicate Close are covered.
The bridge benchmark reports 0 B/op and 0 allocs/op for 1400-byte packets; this
is a packet handoff measurement, not encrypted tunnel throughput.

One wildcard UDP socket supports IPv4 and IPv6 destinations and replies on a
shared ephemeral port. Wildcard TCP listeners support both families and port
zero allocation. Single-family wildcard binds retain their family restriction;
dual binds conflict with existing binds in either family.

The local encrypted interoperability test pairs the production WireGuard
client with a second engine using the original gVisor stack and default UDP
bind. It validates IPv4/IPv6 payloads, bulk TCP upload and reply after FIN,
multiple UDP destinations on one socket, deadlines, cancellation and passive
connections. The harness owns an unmarked loopback transport so host routing
policy does not redirect the test. AmneziaWG's older TUN API has a dual-stack
packet/offset regression. External AmneziaWG servers, remote MASQUE services
and non-Linux runtime are not qualified by these tests.

A valid peer RST now preserves `syscall.ECONNRESET`; relay's existing expected
network-error policy logs it at Debug. Permission failures and other unexpected
errors remain Error. This changes error classification, not RST validation or
TCP state transitions.

## Profiles and implementation

Profiles use separate four-second processes with GOMAXPROCS=4 and heap sampling
at 16KiB. They include process setup and the Linux client. Profile runs are not
included in throughput medians. Raw logs and pprof text are retained in
[wireguard-followup](lightweight-results/wireguard-followup/).

- Baseline allocation objects: `TCPConn.receive` accounts for 64.8%, specifically
  appending every in-order MSS to an empty reordering slice. Ordered input now
  copies directly into the receive queue; overlap, wraparound, FIN and all
  out-of-order handling retain the bounded first-arrival policy.
- Baseline timer allocation: `time.NewTimer` plus its runtime timer accounts for
  about 25.5% of objects. Socket deadlines now share each connection's existing
  scheduler job; changing, clearing or expiring a deadline wakes its direction
  without aborting the transport.
- After those changes, notification `watch` channels account for 89.6% of sampled
  objects. Application reads and writes now serialize independently and reuse
  one lazy buffered signal per direction. State checks and waiter registration
  hold the protocol mutex; Close takes neither application IO mutex. Handshake
  observers retain a separate broadcast channel.
- Ten preallocated 4096-pointer channel arrays cost about 320KiB per stack before
  caching anything. Cache links now live inside charged buffer/segment
  descriptors with class locks. The shared 10MiB-or-MemoryLimit/8 admission
  budget, 4096 entries per class, pressure eviction, idle expiry and output
  wakeups are preserved. Checked-out descriptors have their links cleared.

Fixed connection accounting rises from 5120 to 6144 bytes to conservatively
include IO/handshake signals and SYN/FIN descriptors alongside the controller
and small retained queues. Reflection tests guard descriptor and connection
charges on native and 386 builds. These accounting charges differ from measured
live heap and process RSS.

Intermediate runs retain each step: `native-receive-only`,
`native-shared-deadlines`, `native-linked-cache`, and
`native-reusable-notifications`. The baseline and intermediate comparison use
MTU 1500, 1/100 flows, upload/download, three fresh processes per case, 500ms
per process. No unsuccessful measurements are discarded.

## Final native matrix

Environment: `go version go1.27.2-X:nodwarf5 linux/amd64`; Linux-7.2.6-zen2-1-zen-x86_64-with-glibc2.44; AMD Ryzen 5 5600G;
GOMAXPROCS=4, 500ms per fresh process, three samples per workload. All 270
samples completed (90 workloads: five stacks, three MTUs, three flow counts,
two directions). Tables show medians. Full samples and all metrics are in
[native-final.json](lightweight-results/wireguard-followup/native-final.json).

Matched MTU-1500 CUBIC before/after and final gVisor comparison:

| Flows/direction | CUBIC MB/s before → after | CUBIC B/batch before → after | gVisor B/batch | CUBIC allocs/batch before → after | live heap MiB CUBIC / gVisor | peak RSS MiB CUBIC / gVisor |
|---|---:|---:|---:|---:|---:|---:|
| 1/upload | 384.42 → 405.23 | 4,094 → 34 | 592 | 66 → 0 | 0.75 / 0.81 | 22.04 / 24.65 |
| 1/download | 342.95 → 337.93 | 466 → 58 | 866 | 5 → 0 | 0.81 / 0.99 | 22.32 / 24.77 |
| 100/upload | 487.22 → 522.52 | 562,109 → 86,849 | 204,600 | 6,857 → 69 | 8.16 / 8.41 | 30.35 / 35.33 |
| 100/download | 418.67 → 401.10 | 404,846 → 405,559 | 790,819 | 957 → 545 | 16.34 / 17.88 | 40.69 / 43.60 |

The single-upload allocation reduction is 99.2%; the 100-upload reduction is
84.5% against the matched CUBIC baseline. A reported 0 allocs/op is a rounded
benchmark count; the positive B/batch values retain amortized cache misses.
All 27 Reno/CUBIC/BBR upload workload medians allocate fewer bytes than the
corresponding gVisor workload. All 18 single-flow controller/MTU/direction
comparisons have lower live heap and peak RSS than gVisor in this matrix.

CUBIC download throughput medians are 1.5%/4.2% lower than the matched
single/100-flow baseline. The three-sample ranges overlap (100 downloads:
before 404.50–429.97, after 396.90–430.36 MB/s); this run does not establish
a universal throughput improvement. MTU-9000 uploads remain slower than
gVisor. Every unfavorable sample is retained.

| MTU | Flows | Direction | gVisor MB/s | tun2socket MB/s | Reno MB/s | CUBIC MB/s | BBR v3 MB/s |
|---:|---:|---|---:|---:|---:|---:|---:|
| 1280 | 1 | upload | 295.92 | 172.67 | 369.88 | 372.11 | 371.06 |
| 1280 | 1 | download | 189.01 | 225.56 | 311.09 | 301.00 | 313.53 |
| 1280 | 8 | upload | 376.19 | 180.77 | 469.68 | 468.00 | 468.36 |
| 1280 | 8 | download | 204.60 | 180.78 | 354.20 | 344.42 | 345.91 |
| 1280 | 100 | upload | 379.49 | 175.51 | 466.55 | 466.91 | 469.74 |
| 1280 | 100 | download | 191.86 | 179.40 | 326.27 | 323.73 | 328.53 |
| 1500 | 1 | upload | 330.86 | 197.64 | 404.85 | 405.23 | 403.18 |
| 1500 | 1 | download | 232.97 | 256.53 | 345.76 | 337.93 | 346.27 |
| 1500 | 8 | upload | 430.59 | 222.43 | 524.77 | 524.25 | 529.75 |
| 1500 | 8 | download | 254.11 | 224.70 | 418.11 | 435.48 | 431.56 |
| 1500 | 100 | upload | 439.14 | 209.05 | 524.99 | 522.52 | 519.27 |
| 1500 | 100 | download | 234.58 | 208.08 | 411.64 | 401.10 | 420.51 |
| 9000 | 1 | upload | 875.54 | 745.57 | 777.56 | 769.84 | 776.66 |
| 9000 | 1 | download | 781.02 | 645.10 | 754.70 | 761.24 | 749.15 |
| 9000 | 8 | upload | 1558.33 | 880.55 | 1253.47 | 1258.16 | 1244.15 |
| 9000 | 8 | download | 983.48 | 917.52 | 1476.94 | 1519.56 | 1489.33 |
| 9000 | 100 | upload | 1687.97 | 872.58 | 1320.40 | 1333.70 | 1334.66 |
| 9000 | 100 | download | 963.20 | 892.37 | 1625.09 | 1638.68 | 1634.81 |

The idle run uses 1000 established connections and three fresh processes per
stack. Heap deltas are relative to the stack’s own pre-connection baseline;
the fixed stack allocation is included in total idle heap, not that delta.
[Idle samples](lightweight-results/wireguard-followup/idle-final.json):

| Stack | heap delta bytes/connection | added goroutines/connection | total idle heap MiB |
|---|---:|---:|---:|
| gvisor | 5,081 | 0 | 5.35 |
| tun2socket | 1,027 | 0 | 1.39 |
| reno | 1,607 | 0 | 2.03 |
| cubic | 1,712 | 0 | 2.13 |
| bbr | 2,060 | 0 | 2.47 |

## Reproduction and validation

```sh
go test -c -tags lightweight_kernel -o /tmp/lightweight-followup.test ./pkg/net/proxy/tun/lightweight
python3 scripts/benchmarks/lightweight.py --binary /tmp/lightweight-followup.test \
  --samples 3 --benchtime 500ms \
  --output docs/benchmarks/lightweight-results/wireguard-followup/native-final.txt
python3 scripts/benchmarks/lightweight.py --binary /tmp/lightweight-followup.test \
  --idle --samples 3 \
  --output docs/benchmarks/lightweight-results/wireguard-followup/idle-final.txt
```

The runner creates isolated user/network namespaces and records binary SHA256,
Go version, host environment and every sample. Linux TCP runs in the same
process as the userspace stack. No offload is enabled. Allocation is per
completed batch (64KiB times the flow count); heap is sampled after GC while
connections are alive, and peak RSS uses process rusage. Profiling/compilation
and tests run separately from timed comparisons. Short-run P95/P99 values are
retained but do not establish long-duration tail behavior. Local no-offload
throughput does not predict encrypted or remote-tunnel throughput.

Validation covers race tests, independent gVisor and Linux TCP peers, IPv4/IPv6,
UDP fragmentation, ICMP, continuous PMTU reduction, output admission/eviction,
metadata budgets, deadlines and concurrent reads at data/FIN/RST/Close. The
full Go suite, 386 core tests, workflow-pinned golangci-lint v2.14.0 and go fix
are run locally. The first full integration run had a TLS compatibility timeout;
the subsequent full run passed. The CI qualification job exercises sustained
BBR coexistence and changing bandwidth separately from performance claims.

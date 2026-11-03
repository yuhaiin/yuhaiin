# Pluggable TCP recovery: measurements and validation

Measurement date: **2026-11-03**. These measurements compare `classic` with
`rack-tlp` on the same working tree. Raw samples, medians, Go-source SHA-256,
base revision and environment are retained in
[data/tcp-recovery-2026-11-03](data/tcp-recovery-2026-11-03/metadata.json).

## Environment and scope

Linux 7.2.6-zen2-1-zen, amd64, Go 1.27.3, `GOMAXPROCS=4`, three samples per
case, and a 500ms Go benchmark target per sample. Cases run sequentially.
The Linux peer is the independent host TCP implementation in an isolated
user/network namespace, using a plain IP TUN, MTU 1500, without offload or VPN
encryption. The impaired peer is gVisor behind the existing seeded delay,
jitter and loss simulator. Neither setup measures a physical Internet link or
an encrypted VPN's end-to-end performance. Kernel upload means Linux sends
to Lightweight; kernel download means Lightweight sends to Linux.

## Deterministic tail-loss repair

The raw-wire virtual-time test establishes a 10ms RTT, sends one 64-byte data
segment and drops it. The classic mode retransmits after its 1s minimum RTO;
RACK-TLP probes after 220ms, including its conservative 200ms single-segment
delayed-ACK budget. This is **virtual protocol time**, not a measured network
latency distribution or a promise about arbitrary paths.

| Detector | Time until retransmission |
| --- | ---: |
| classic | 1000ms |
| rack-tlp | 220ms |

[Raw virtual-time test](data/tcp-recovery-2026-11-03/tail-latency.txt).

## Independent Linux TCP throughput

Median application payload throughput, decimal MB/s. No loss was injected.
One of the 36 retained kernel samples reported one retransmission; the other
samples reported none. The direction and size of throughput differences vary
between short runs. These results do not establish a general RACK-TLP
throughput improvement. Detector CPU cost is measured separately below.
Both modes reported zero rounded allocations per operation in this workload.

| Controller | Direction | classic MB/s | rack-tlp MB/s | Change |
| --- | --- | ---: | ---: | ---: |
| RENO | upload | 401.20 | 390.22 | -2.7% |
| RENO | download | 374.33 | 388.49 | +3.8% |
| CUBIC | upload | 401.66 | 404.33 | +0.7% |
| CUBIC | download | 390.83 | 404.00 | +3.4% |
| BBR | upload | 401.79 | 401.47 | -0.1% |
| BBR | download | 375.54 | 391.65 | +4.3% |

[Classic raw samples](data/tcp-recovery-2026-11-03/kernel-classic.txt) and
[RACK-TLP raw samples](data/tcp-recovery-2026-11-03/kernel-rack-tlp.txt).

## Detector CPU cost

This microbenchmark passes the same borrowed metadata view to each detector,
without packet parsing, sockets or transmission. It measures an ACK with no
SACK blocks: classic has no scoreboard scan to perform, whereas RACK examines
the flight. RACK's current scan grows with outstanding segment count. The
4096-segment result exposes a future optimization opportunity; zero allocation
does not imply negligible CPU cost on large bandwidth-delay-product paths.

| Outstanding segments | classic ns/op | rack-tlp ns/op | Allocations/op, classic / rack-tlp |
| ---: | ---: | ---: | ---: |
| 16 | 37.56 | 411.40 | 0 / 0 |
| 256 | 37.49 | 6006.00 | 0 / 0 |
| 4096 | 37.52 | 95372.00 | 0 / 0 |

[Raw detector samples](data/tcp-recovery-2026-11-03/detector.txt).

## Impaired gVisor peer

The existing workload transfers 64KiB application messages. The 10ms profile
has no injected loss; the 50ms profile adds 1ms jitter and a seeded 0.1% loss
probability. Short runs may observe no random packet loss, and different
packet timing changes the number of random decisions. Retained loss counts
therefore differ between cases. In particular, jitter can trigger traditional
fast retransmission even when the simulator reports no drops. These samples
are a regression/profiling fixture, not a controlled estimate of a universal
RACK-TLP speedup. The latency column is the median of each sample's p95, not
a pooled percentile. Inspect per-sample drops and retransmissions in the raw
records before interpreting throughput differences.

| Profile | Controller | classic MB/s | rack-tlp MB/s | p95 ms, classic / rack-tlp |
| --- | --- | ---: | ---: | ---: |
| rtt10ms | RENO | 5.86 | 5.80 | 11.39 / 11.43 |
| rtt10ms | CUBIC | 3.08 | 3.09 | 21.81 / 21.79 |
| rtt10ms | BBR | 3.81 | 3.82 | 19.76 / 19.61 |
| rtt50ms-loss0.1pct | RENO | 0.17 | 1.01 | 407.15 / 151.69 |
| rtt50ms-loss0.1pct | CUBIC | 0.15 | 0.59 | 507.68 / 302.61 |
| rtt50ms-loss0.1pct | BBR | 0.66 | 0.64 | 178.63 / 177.32 |

[Raw impaired samples](data/tcp-recovery-2026-11-03/impaired.txt) and
[all samples and computed medians](data/tcp-recovery-2026-11-03/summary.json).

## Correctness coverage

- Both detectors against an independent gVisor TCP peer with loss, duplication,
  reordering, IPv4/IPv6, active/passive connection setup and half-close.
- Both detectors against Linux TCP over an isolated TUN, IPv4/IPv6, both dial
  directions, UDP/ICMP and continuous PMTU changes.
- Raw-wire and virtual-time tests for small-flight recovery, tail selection,
  unsuccessful probes falling back to RTO, reordering without retransmission,
  SACK negotiation fallback, SYN retransmission, sequence wrap and re-loss.
- DSACK generation below/above the cumulative ACK, preservation of normal SACK
  evidence, conservative complete-recovery proof and BBR undo through real ACKs.
- Shared settings persistence for all 16 VPN protocol configurations, and
  configured CUBIC/RACK-TLP through two real encrypted WireGuard engines.
- Memory-charge assertions include detector state; race tests exercise the
  core, congestion/recovery modules and shared VPN adapters.

## Reproduce

Run from the backend repository on Linux with a usable `/dev/net/tun`, `ip`,
and unprivileged user/network namespaces. The `--kernel` option requires those
capabilities and fails if unavailable; it does not silently skip the cases.
Podman is not required because the runner already isolates kernel networking.

```sh
python3 scripts/benchmarks/tcp_recovery.py --kernel --output /tmp/tcp-recovery-results
```

Omit `--kernel` to run only portable detector/reference-peer measurements.
Use `--samples`, `--benchtime` and `--gomaxprocs` to change sampling parameters;
retain the generated metadata with any published comparisons.

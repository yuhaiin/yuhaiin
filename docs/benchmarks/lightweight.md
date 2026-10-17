# Lightweight TCP/IP stack: consolidated benchmarks

Latest retained measurement date: **2026-10-17**. This report combines the original audit, BBR v3/recovery work, Linux offload/ownership optimization, platform research and native checksum A/B. It describes the implementation as measured on the specified commits; it does **not** guarantee that every number remains representative after later changes. For the maintained architecture and VPN integrations, see [the stack documentation](../lightweight-tcpip-stack.md).

## Current implementation and boundaries

- The `lightweight` TCP/IP core includes separate Reno, CUBIC + HyStart++ and BBR v3 congestion controllers, pacing, SACK/recovery and PMTU handling; `bbr` denotes **BBR v3**, not the older v1 checkpoint. The controller is based on Google's `bbr-v3-2026-09-16-01` reference (commit `674859761ded9f32690c7bdaf22ef585531452ed`). See [BBR attribution and license](../../licenses/bbr-v3.md).
- The Linux-created TUN path can negotiate virtio network headers, TCPv4/v6 segmentation offload and checksum metadata, falling back to plain packets. Supplied descriptors retain their actual framing/capabilities. UDP segmentation offload, multiqueue and jumbo shortcuts were **not** enabled by this change.
- Packet handling uses bounded, validated borrowed input views and owned output buffers with device headroom. The macOS utun path reserves its four-byte prefix; the ordinary Android VpnService descriptor remains plain packet I/O without Linux offload negotiation. Asynchronous queues never retain a borrowed application Write slice.
- Transport changes include corrected first SACK-block selection, bounded output/memory budgets, more efficient transmit-prefix lookup and queued notifications, and independent control of packet ownership/retransmission. Correctness gates remain more important than optimistic benchmark shortcuts.
- Native checksum dispatch uses baseline amd64 carry arithmetic and arm64 NEON assembly for large inputs, with a portable Go fallback (including short inputs/tails). It preserves odd-byte, alignment, seed and one's-complement semantics. **arm64 performance was not measured on physical hardware**; QEMU is functional evidence, not a speed benchmark.

## Independent-process Linux comparison (MTU 1500)

The 2026-10-17 series used Ryzen 5 5600G, Linux 7.2.6-zen2-1-zen, Go 1.27.2, independent client/proxy/SOCKS backend/iperf3 target, three five-second runs per case, controlled CPU affinities and fresh rootless network namespaces. The pinned hev revision was `873541b81f00f8fd462392fc622adbb8a8cd59b0` (and its pinned submodules). Performance numbers are median **Gbit/s**, application TCP payload; upload/download are from the test client. They omit encryption and full application routing.

| Implementation / mode | 1 upload | 1 download | 8 upload | 8 download |
| --- | ---: | ---: | ---: | ---: |
| Before: lightweight CUBIC, plain | 4.41 | 3.00 | 4.50 | 3.81 |
| Before: lightweight BBR v3, plain | 4.43 | 0.92 | 4.47 | 2.46 |
| After: lightweight CUBIC, plain | 4.95 | 4.53 | 5.12 | 3.91 |
| After: lightweight BBR v3, plain | 4.97 | 3.91 | 5.17 | 3.72 |
| After: lightweight CUBIC, TCP GSO | 23.26 | 18.24 | 42.46 | 20.00 |
| After: lightweight BBR v3, TCP GSO | 23.57 | 12.37 | 41.80 | 9.88 |
| hev/lwIP, plain | 3.52 | 3.33 | 3.28 | 3.41 |
| hev/lwIP, TSO | 21.30 | 21.27 | 19.92 | 20.77 |

The before/after implementation checkpoint was `29be8d0f` → `bb04f0bc`. **The BBR GSO download deficit remains visible**: CUBIC GSO and hev TSO download better in this particular configuration. No row establishes an absolute userspace performance ceiling. Hev's plain/TSO modes are distinct configurations and must not be collapsed into a single baseline.

Proxy-process CPU seconds per transferred GiB/GB-equivalent unit as recorded by the runner (reported as `CPU s/GB`):

| Implementation | 1 upload | 1 download |
| --- | ---: | ---: |
| Before CUBIC, plain | 3.81 | 4.73 |
| Before BBR, plain | 3.77 | 11.66 |
| After CUBIC, plain | 3.31 | 3.55 |
| After BBR, plain | 3.31 | 3.88 |
| After CUBIC, GSO | 0.57 | 0.71 |
| After BBR, GSO | 0.57 | 1.02 |
| hev plain | 2.11 | 2.29 |
| hev TSO | 0.31 | 0.30 |

Inspect recorded environment and precise medians in [hev baseline](data/hev-baseline.summary.json), [pre-optimization](data/offload-before.summary.json) and [optimized](data/offload-after.summary.json). The hev baseline is an earlier independently sampled fixture, while the before/after rows above come from the controlled optimization comparison.

## Native checksum follow-up (2026-10-17)

The next follow-up to `bb04f0bc` isolates the native checksum implementation. On amd64, microbenchmarks measured nanoseconds per checksum call:

| Input size | Portable Go | Native amd64 | Speedup |
| --- | ---: | ---: | ---: |
| 40 B | 9.623 ns | 10.09 ns | 0.95× |
| 1500 B | 221.0 ns | 62.03 ns | 3.56× |
| 65535 B | 9175 ns | 2337 ns | 3.93× |

The short-input regression is why the short portable path remains. Whole-proxy gains are smaller because checksum is only one part of packet processing. Separate interleaved A/B tests (MTU 1500, one flow) measured:

| Mode / direction | Portable Gbit/s | Native Gbit/s | Portable CPU s/GB | Native CPU s/GB |
| --- | ---: | ---: | ---: | ---: |
| CUBIC upload | 4.91 | 5.25 | 3.340 | 3.181 |
| CUBIC download | 4.48 | 4.49 | 3.587 | 3.580 |
| GSO-CUBIC upload | 21.90 | 23.19 | 0.607 | 0.576 |
| GSO-CUBIC download | 18.45 | 17.72 | 0.707 | 0.743 |

The last row is a **regression**, not an improvement. These are interleaved local samples, not evidence that the native checksum path accelerates every workload. Metadata and medians are retained in [checksum-native.summary.json](data/checksum-native.summary.json).

## Correctness, platform notes and unresolved work

The recorded verification covered independent Linux TCP peers, IPv4/IPv6, all three controllers, SACK/PMTU, UDP/ICMP, socket lifecycle and races, portable checksum reference cases and fuzzing, 386 tests, cross-builds, and the relevant full Go/lint checks. These are **historical pass records**, not a CI status assertion for this PR.

- On Linux TUN, `readv` scatters **one packet** and `writev` gathers **one packet**; these are not arbitrary packet batching operations. `sendmmsg`/`recvmmsg` do not turn the TUN character device into a socket. Validate virtio headers and retained GSO metadata at the actual descriptor boundary.
- macOS utun needs a four-byte address-family prefix; Android VpnService's framework-created descriptor does not negotiate Linux VNET/TSO. Emulator throughput does not predict battery use or physical-device thermal behavior.
- [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html), [RFC 2018](https://www.rfc-editor.org/rfc/rfc2018.html), [RFC 6675](https://www.rfc-editor.org/rfc/rfc6675.html), [RFC 8985](https://www.rfc-editor.org/rfc/rfc8985.html), [RFC 9438](https://www.rfc-editor.org/rfc/rfc9438.html) and [RFC 9768 (AccECN)](https://www.rfc-editor.org/rfc/rfc9768.html) inform conformance and future work. Timestamp/PAWS, RACK/TLP, PLPMTUD, recovery fairness and multiple queues require further design and independent tests. AccECN and ACK-rate negotiation are not automatic throughput switches.
- Remaining performance opportunities include vectored receive drain with explicit lifetime accounting, flow-affine execution and multi-queue benchmarking, and improving the BBR GSO download path. Guard against increased allocation, latency and tail loss when changing batching.

## Reproduce

From the repository root on a suitable Linux host, with `unshare`, `ip`, `taskset`, `iperf3`, `/dev/net/tun` and a pinned hev shared library:

```sh
go build -o /tmp/stackprobe-native ./scripts/benchmarks/stackprobe
python3 scripts/benchmarks/hev_compare.py \
  --probe /tmp/stackprobe-native \
  --hev-lib /path/to/libhev-socks5-tunnel.so \
  --stacks cubic bbr gso-cubic gso-bbr hev-plain hev-tso \
  --flow-counts 1 8 --samples 3 --seconds 5 \
  --output /tmp/lightweight-compare.jsonl
```

For the **checksum-only A/B**, build the portable version via the overlay helper. Use the comparison harness with matching workloads and non-overlapping build/test activity:

```sh
python3 scripts/benchmarks/checksum_portable.py build \
  -o /tmp/stackprobe-portable ./scripts/benchmarks/stackprobe
go build -o /tmp/stackprobe-native ./scripts/benchmarks/stackprobe
python3 scripts/benchmarks/hev_compare.py \
  --probe /tmp/stackprobe-portable --compare-probe /tmp/stackprobe-native \
  --hev-lib /path/to/libhev-socks5-tunnel.so \
  --stacks cubic gso-cubic --flow-counts 1 --samples 3 --seconds 5 \
  --output /tmp/checksum-ab.jsonl
```

Use `python3 scripts/benchmarks/hev_compare.py --help` for supported stack names and machine-specific tuning. Do not append new run logs to Git; retain new machine-readable **summaries** and revise this report after code changes.

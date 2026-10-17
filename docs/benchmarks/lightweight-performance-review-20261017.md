# Baseline lightweight stack performance audit

Audit date: 2026-10-17. Baseline production source: `29be8d0f`. The pinned hev
revision is `873541b81f00f8fd462392fc622adbb8a8cd59b0`, including its recorded
lwIP and task-system submodules. This document describes the **pre-optimization**
implementation. See the [optimization report](lightweight-offload-optimization-20261017.md)
for the implemented changes and follow-up measurements.

## Method and interpretation

Each sample uses a fresh rootless `unshare -Urn` namespace and independent
client, tested proxy, common SOCKS backend and target processes:

```text
iperf3 client -> bench0 (198.18.0.2:5201) -> lightweight / hev
             -> common SOCKS5 (127.0.0.1:1080) -> iperf3 (127.0.0.1:5201)
```

The SOCKS fixture accepts only the benchmark target and maps it to loopback,
preventing recursive TUN routing. Traffic is local IPv4 TCP without encryption or
a physical NIC. Upload means client to server. No host default routes change.

- Host: Ryzen 5 5600G, Linux `7.2.6-zen2-1-zen`, Go `1.27.2-X:nodwarf5`.
- Proxy affinity: CPU 0-2, client 3, common backend 4, target 5. SMT siblings
  are 0/6 through 5/11. Go uses `GOMAXPROCS=3`; hev runs one instance.
- MTU 1500, one TUN queue, `txqueuelen=10000`, three fresh five-second samples
  per case; deterministic shuffled order. All 96 samples are retained.
- The baseline helper includes the core, a minimal SOCKS bridge and a simulated
  production adapter copy. It excludes full yuhaiin routing, DNS and telemetry.
  It does not establish complete application performance.
- Lightweight uses LocalTun defaults; hev retains its default buffers. Algorithms,
  buffer policies and validation work differ. Hev's pinned lwIP disables input
  IP/TCP/UDP checksum checks, even in the plain group. Our raw-wire validation
  remains enabled; this is an actual-implementation comparison.
- CPU s/GB measures only tested-proxy user+system CPU per decimal payload GB,
  excluding client/backend/target. It is not total host energy. RSS is VmHWM;
  hev includes a fixed Python ctypes launcher overhead and cannot represent
  native CLI minimum RSS. Initialization completes before timing.
- Iperf reports received payload goodput, not byte-pattern validation or WAN
  fairness. Separate protocol tests and Android integrity probes cover other
  properties. Five-second samples do not establish sustained p99 latency.

## Baseline results

Median received goodput, Gbit/s:

| Implementation / device | 1-flow upload | 1-flow download | 8-flow upload | 8-flow download |
|---|---:|---:|---:|---:|
| Lightweight CUBIC / plain | 4.44 | 2.81 | 4.43 | 2.72 |
| Lightweight BBR v3 / plain | 4.45 | 0.96 | 4.44 | 2.40 |
| Hev / plain fd | 3.51 | 3.24 | 3.27 | 3.36 |
| Hev / VNET checksum only | 3.38 | 3.33 | 3.15 | 3.32 |
| Hev / VNET + TSO | 22.44 | 21.56 | 20.64 | 20.52 |
| Hev / plain fd + local jumbo | 3.53 | 19.52 | 3.26 | 19.00 |
| Common SOCKS + bridge, no TUN | 49.45 | 49.25 | 48.97 | 48.87 |
| Direct kernel loopback | 55.36 | 55.07 | 49.28 | 49.59 |

Median single-flow tested-proxy CPU s/GB, lower is better:

| Implementation | Upload | Download |
|---|---:|---:|
| Lightweight CUBIC / plain | 3.79 | 5.02 |
| Lightweight BBR v3 / plain | 3.77 | 11.24 |
| Hev / plain fd | 2.11 | 2.35 |
| Hev / checksum only | 2.23 | 2.29 |
| Hev / TSO | 0.30 | 0.30 |
| Hev / local jumbo | 2.12 | 0.34 |

Under these settings, baseline CUBIC upload exceeds hev plain throughput but
uses more proxy CPU per GB; download trails hev plain. Hev TSO is about 5.05x
faster uploading and 7.68x downloading than baseline CUBIC plain. This includes
I/O capability, checksum-policy, implementation and runtime differences. It
cannot all be attributed to congestion control, or to memcpy.

Checksum-only does not produce an order-of-magnitude gain. Local jumbo mostly
helps download, whereas TSO helps both directions. This supports retaining
larger records and reducing per-packet work. Direct and SOCKS-only controls
show fixture headroom; neither is a userspace theoretical ceiling.

Samples fluctuate: CUBIC eight-flow download measured 3.812, 2.725 and 2.699
Gbit/s. Use distributions/raw records rather than precise short-run promises.
[Raw samples and summaries](lightweight-results/hev-20261017/).

## Profile findings

Four separate five-second single-flow profiles are excluded from formal medians.
[CUBIC download](lightweight-results/hev-20261017/profiles/cubic-1500-1-download-1.top.txt)
has 43.92% syscall flat samples, 9.98% `pump`, 7.45% `schedule`, 8.49% `sumBytes`,
and only 1.15% `runtime.memmove`.
[BBR download](lightweight-results/hev-20261017/profiles/bbr-1500-1-download-1.top.txt)
has 31.50% `schedule`, 12.48% `pump`, 20.36% syscall and 3.71% `sumBytes`.
These are CPU sample shares, not wall-clock pauses or cumulative percentages.

The [schedule line profile](lightweight-results/hev-20261017/profiles/bbr-schedule.lines.txt)
locates repeated full retained-TX-queue scans in `tcp_timer.go`, rather than heap
operations. Prioritize avoiding scans of already-sent data on every ACK/pacing
wake. Linux per-packet syscall cost also motivates GSO. Adapter copy removal
has structural value, particularly for macOS, but memcpy is not the largest
measured Linux bottleneck.

## Baseline code findings and implemented follow-up

| Baseline behavior | Follow-up in this change |
|---|---|
| Linux opener explicitly excludes VNET and adapter rejects GSO | Validated optional Linux checksum/TCP segmentation path with plain fallback |
| Adapter buffer -> core scratch copy; native utun adds another copy | Synchronous borrowed packet views, retaining owned receive queues |
| macOS four-byte prefix requires temporary full-packet copy | Reserve prefix space in owned output storage |
| TX admission scans all retained descriptors repeatedly | Binary-search sent prefix; scan repairs only while pending |
| Per-16-bit software checksum loop | Portable wider-word accumulation, independent checksum-reference tests |
| Cache classes stop at 16 KiB | Bounded 32/64 KiB classes under the existing total cache/memory limits |
| SACK selects lowest sequence blocks, omitting the most recent range | Arrival-aware first block, merged ranges, duplicate/wrap regression tests |

The original [SACK failing output](lightweight-results/hev-20261017/sack-reproducer.txt)
records the pre-fix result: arrival 1001 still advertised 201 first and omitted
the newest range when five disjoint ranges existed.
[RFC 2018 section 4](https://www.rfc-editor.org/rfc/rfc2018.html#section-4)
requires the first block to cover the triggering segment when the cumulative
ACK does not advance. Permanent tests now cover this; the temporary Go-overlay
probe has been removed.

## Android baseline validation

An isolated, ordinary app receives a real VpnService fd and passes it with
SCM_RIGHTS to a native Go child. Java traffic generation and the native stack
use separate processes. SELinux remains Enforcing in `untrusted_app_32`.
Both images report flags `0x1001` (TUN + NO_PI), no VNET, and denial of
`TUNSETOFFLOAD(0)`. The probe explicitly binds sockets to the VPN `Network`.

Each cell contains three timed 256 MiB samples per direction plus 16 MiB
warmup per direction. Every payload and completion marker is checked. Across
two images and two MTUs, timed validation totals 6 GiB.

| Emulator | MTU | Upload median Gbit/s | Download median Gbit/s | Integrity |
|---|---:|---:|---:|---|
| Android 14 / 4 KiB pages | 1500 | 2.22 | 2.24 | 6/6 passed |
| Android 14 / 4 KiB pages | 9000 | 5.55 | 3.55 | 6/6 passed |
| Android 15 / 16 KiB pages | 1500 | 5.40 | 3.34 | 6/6 passed |
| Android 15 / 16 KiB pages | 9000 | 10.33 | 8.77 | 6/6 passed |

[API 34 records](lightweight-results/hev-20261017/android-api34/),
[API 35 records](lightweight-results/hev-20261017/android-api35-16k/).
Native-log NUL terminators are escaped as `\0` for text inspection.
The initial API 35 attempt selected the default underlay rather than the VPN;
its failure is retained separately and was fixed by explicit VPN selection.
It is not evidence of a 16 KiB stack defect.

This is a subsecond diagnostic integrity probe without SOCKS or an Android hev
comparison. JVM/virtualization variance is substantial. It is not comparable to
the Linux main table, a physical arm64 device, sustained thermal performance,
or an isolated page-size experiment. MTU 9000 remains diagnostic; no default
MTU change follows. macOS has source/API research only.

## Reproduction and remaining directions

```sh
git clone --recursive https://github.com/heiher/hev-socks5-tunnel.git /tmp/hev-stack-review
git -C /tmp/hev-stack-review checkout 873541b81f00f8fd462392fc622adbb8a8cd59b0
git -C /tmp/hev-stack-review submodule update --init --recursive
make -C /tmp/hev-stack-review -j4 shared
go build -o /tmp/yuhaiin-stackprobe ./scripts/benchmarks/stackprobe
python3 scripts/benchmarks/hev_compare.py \
  --probe /tmp/yuhaiin-stackprobe \
  --hev-lib /tmp/hev-stack-review/bin/libhev-socks5-tunnel.so \
  --stacks direct socks cubic bbr gso-cubic gso-bbr hev-plain hev-tso \
  --flow-counts 1 8 --seconds 5 --samples 3 \
  --output /tmp/hev-compare.jsonl
```

The current helper exercises the production adapter; this command reproduces
its current behavior, not historical baseline source. Use the recorded baseline
revision/helper provenance to reproduce the earlier matrix. Adjust affinities
to physical CPU topology. The runner preopens genuine plain or VNET fds instead
of relying on hev CLI defaults. `hev-csum` and `hev-jumbo` isolate other modes.
`--profile-dir` collects separate profiles; profiling samples must not enter the
formal throughput table. Podman can host the fixture; rootless namespaces were
sufficient here.

The [Android README](../../scripts/benchmarks/android-vpn-probe/README.md) documents
SDK/NDK construction and the consent/integrity workflow. Test apps and temporary
emulators are removed after measurement.

Further work includes stream vectored drain/rings with explicit leases,
timestamp/PAWS, RACK/TLP, PLPMTUD, and flow-affine execution/multiqueue. These
need independent recovery/lifetime/fairness tests. Ordinary delayed ACK already
exists (two receive events or 20 ms); unnegotiated ACK ratios of 32/64 are not a
safe optimization. The [platform research](lightweight-platform-research-20261017.md)
records writev/readv semantics, platform limits, current RFC/draft status and
why local split-TCP and remote tunnel congestion control differ.

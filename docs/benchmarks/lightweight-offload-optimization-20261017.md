# Lightweight stack: offloads, packet ownership and scheduling

Date: 2026-10-17. Baseline: `29be8d0f`; hev:
`873541b81f00f8fd462392fc622adbb8a8cd59b0` with its pinned submodules.
The [baseline audit](lightweight-performance-review-20261017.md) explains the
original bottlenecks; [platform research](lightweight-platform-research-20261017.md)
records API semantics and RFC/draft follow-ups.

## Changes

Linux-created TUNs negotiate virtio headers, checksum offload and TCPv4/v6 GSO,
with a plain fallback if negotiation fails. Supplied descriptors are duplicated,
queried and interpreted using their existing framing. Android's plain framework
VPN descriptor never attempts offload negotiation. VNET metadata is validated
before exposing a trusted transport checksum state; raw-wire traffic retains
checksum checks. Malformed consumed records are dropped without closing the
link. UDP segmentation offload, multiqueue and jumbo shortcuts are not enabled.

The core accepts optional borrowed input views and owned output buffers with
reserved device prefix space. Linux keeps kernel TCP super-packets intact;
macOS's single-packet native path lends its slab and uses four-byte utun headroom.
Queued receive data remains separately owned; no asynchronous code borrows an
application Write slice. Legacy complete-packet reads finish partial checksums
before discarding metadata. These contracts avoid extra adapter copies without
changing ordinary PacketIO callers.

New contiguous, immutable views from one Write allocation may form one output
GSO record. Wire MSS, cwnd, receive window, pacing quantum and the 64-logical-packet
work budget bound each group. The sender keeps individual MSS descriptors and
cumulative-ACK ownership for retransmission, partial ACK and PMTU repair.
SYN/FIN/RST and retransmissions retain ordinary packet output. GSO Write owners
can reach 64 KiB, supported by bounded 32/64 KiB cache classes under the existing
shared memory/cache limits. Prefix and descriptor metadata are accounted.

The TX queue's transmitted entries form a prefix. Binary search identifies the
next unsent entry; only pending loss/PMTU repairs trigger scans of the sent
prefix. This removes the repeated full-backlog scans identified in the BBR
profile. Queue compaction and partial ACK do not require cursor repair.

Software checksums use portable wider-word loads with bounded accumulation,
including odd/unaligned input. Independent gVisor checksum tests cover all-ones,
random seeded sums and lengths through 1 MiB; this also fixes overflow for large
inputs to the exported Checksum helper. No assembly or unsafe alignment is used.

SACK options now prioritize the most recently received range, merge adjacent
pieces and retain recent history independently of sequence sorting. Regression
tests include five disjoint ranges, duplicates, middle arrivals, merged ranges
and sequence wrap, following RFC 2018 section 4.

## Measurement method

The follow-up uses the audit's independent-process rootless namespace topology,
CPU affinities, MTU 1500, one/eight flows, five seconds and three fresh samples
per case. Upload/download refer to iperf client/server. Emulators, builds,
profilers and qualification tests are stopped before timed runs. The original
baseline probe binary is retained and rerun; the optimized probe uses the actual
production opener and packet adapter. Binary hashes, source labels, source
revision, worktree state, hev revision/submodules, offload logs, CPU and all
iperf intervals are retained with each run.

This measures the lightweight core plus a minimal SOCKS bridge, excluding full
application DNS/routing/telemetry. The common SOCKS backend and target are
separate processes. Traffic is local IPv4 TCP without encryption or physical
NIC traversal. CPU s/GB counts only tested-proxy user+system CPU per decimal
payload GB. Hev's lwIP disables input checksum checks and its launcher adds a
fixed Python RSS overhead. Differences include these implementation choices;
this is not an equal-feature algorithm comparison or an absolute stack ceiling.

To build a historical core with the current fixture without changing the checkout:

```sh
python3 scripts/benchmarks/build_baseline_probe.py --ref 29be8d0f \
  --output /tmp/stackprobe-baseline
go build -o /tmp/stackprobe-optimized ./scripts/benchmarks/stackprobe
```

The overlay retains only the optional interface declarations needed by the current
adapter; the historical core ignores those interfaces and uses complete-packet
reads/writes. Use plain `cubic bbr` modes for that historical core. This rebuild
uses the current fixture, whereas the recorded `before` run uses the original
audit fixture binary; binary identity and source labels distinguish them.

## Results

Median received goodput, Gbit/s (24 baseline samples and 72 follow-up samples):

| Implementation | 1-flow upload | 1-flow download | 8-flow upload | 8-flow download |
|---|---:|---:|---:|---:|
| Before: CUBIC plain | 4.41 | 3.00 | 4.50 | 3.81 |
| Before: BBR plain | 4.43 | 0.92 | 4.47 | 2.46 |
| After: CUBIC plain | 4.95 | 4.53 | 5.12 | 3.91 |
| After: BBR plain | 4.97 | 3.91 | 5.17 | 3.72 |
| After: CUBIC GSO | 23.26 | 18.24 | 42.46 | 20.00 |
| After: BBR GSO | 23.57 | 12.37 | 41.80 | 9.88 |
| Hev plain | 3.52 | 3.33 | 3.28 | 3.41 |
| Hev TSO | 21.30 | 21.27 | 19.92 | 20.77 |

Median single-flow proxy CPU s/GB (lower is better):

| Implementation | Upload | Download |
|---|---:|---:|
| Before: CUBIC plain | 3.81 | 4.73 |
| Before: BBR plain | 3.77 | 11.66 |
| After: CUBIC plain | 3.31 | 3.55 |
| After: BBR plain | 3.31 | 3.88 |
| After: CUBIC GSO | 0.57 | 0.71 |
| After: BBR GSO | 0.57 | 1.02 |
| Hev plain | 2.11 | 2.29 |
| Hev TSO | 0.31 | 0.30 |

Relative to the fresh baseline rerun, single-flow CUBIC GSO gains 5.28x upload
and 6.08x download, with about 6.6x less proxy CPU per GB in both directions.
The plain CUBIC path improves about 12% uploading and 51% downloading; plain BBR
single-flow download improves about 4.27x. These gains combine scheduling,
checksums, adapter ownership and, for GSO, fewer per-packet operations.

CUBIC GSO reaches about 86% of hev TSO's single-flow download and 96% of its
eight-flow download in this fixture. Its eight-flow upload exceeds the single
hev instance's throughput, while using about 2.57 proxy cores versus hev's 0.76.
Both have the same CPU 0-2 affinity budget; hev remains a single event-loop
instance. This does not establish better single-core efficiency: our single-flow
GSO CPU/GB remains about 1.8x hev uploading and 2.3x downloading. Hev's disabled
input checksum checks and different storage/runtime policies also matter.

BBR GSO download remains less consistent and slower than CUBIC, especially
with eight flows. Across the three single-flow GSO BBR download samples, goodput
ranges from 11.95 to 18.05 Gbit/s; its median is 12.37. The full
raw distributions are retained; this short local benchmark does not establish
steady-state latency, WAN fairness or a theoretical userspace limit. Earlier
SOCKS-only/direct controls were approximately 49/55 Gbit/s in the audit; they
are historical controls, not additional samples in this follow-up matrix.


## Profile follow-up

Five separate download profiles are excluded from formal throughput medians.
In plain BBR single-flow download, `schedule` flat samples fall from 31.50% in
the baseline to 1.05%, and `pump` from 12.48% to 1.48%. Syscalls now account for
55.27% flat samples. This supports the TX scan fix; profile shares are not
wall-clock speedup predictions. In the eight-flow BBR GSO profile, syscall flat
samples remain 52.10%, with memmove at 8.23% and schedule at 1.22%. Further I/O,
copy and aggregation/pacing work merits investigation; these samples alone do
not establish the exact cause of BBR's remaining throughput gap.
[Profiles and top reports](lightweight-results/optimization-20261017/profiles/).

## Android and macOS scope

The production borrowed-input path was exercised through a real VpnService fd
as an ordinary Enforcing app on Android 14/4 KiB and Android 15/16 KiB x86_64
AVDs. Both MTU 1500 and diagnostic MTU 9000 run three 256 MiB uploads and three
downloads with payload/marker checking, totaling 6 GiB plus warmups. Both report
`IFF_TUN|IFF_NO_PI` (`0x1001`), no VNET, and denial of `TUNSETOFFLOAD(0)`.
Logs and APK provenance are in the result directory. APK provenance explicitly
identifies a later legacy-read compatibility fix that does not execute on the
borrowed-input Android path; Linux kernel tests cover that legacy API separately.

These Android probes demonstrate integrity and framework-fd behavior. They are
not a controlled phone-performance A/B: some transfers are subsecond, JVM/VM
variance is substantial, and the two images differ beyond page size. API 35's
first activity was killed by Android lowmemorykiller during cold boot before
native startup; relaunching after boot completed passed. No root/SELinux changes
were made. Test APKs and temporary emulator instances are removed afterwards.
The production macOS adapter and core cross-compile for darwin/arm64, but no Mac
runtime or physical arm64 Android throughput is claimed. Default MTU is unchanged.

## Validation

- Full TUN tree race tests, protocol/resource/ownership tests and independent
  reference peers pass. New coverage checks SACK recency, GSO admission bounds,
  logical accounting, checksum trust, prefix ownership and complete-packet API.
- Linux kernel peers exercise IPv4/IPv6, Reno/CUBIC/BBR, active/passive TCP,
  byte-pattern echo and half-close with offload counters proving large input
  and segmented output. Every combination also drops one complete output GSO
  record and requires retransmission/recovery. CUBIC active cases additionally
  exercise legacy input checksum completion. UDP fragments and ICMP pass.
- Existing kernel TCP/UDP/ICMP/PMTU and native-device lifecycle suites pass in
  separate namespaces under race instrumentation. CI includes the new offload suite.
- ParsePacket, TCPOptions and virtio metadata fuzzing pass; CI runs all three.
- Sustained BBR shared-bottleneck and changing-bandwidth race qualification passes.
- The portable core builds for Linux amd64/arm64/386/mipsle, macOS arm64, Windows
  amd64, Android arm64 and iOS arm64. Production TUN adapters also build for
  macOS arm64, Android arm64 and Linux 386; Linux 386 core tests pass.
- Full `go test ./...`, workflow-pinned golangci-lint v2.15.0, actionlint v1.7.12,
  benchmark smoke and `go fix ./...` pass. Go fix makes no source changes.
  The user-authorized removal of an ignored, obsolete local tcplife/test fixture
  clears a pre-existing missing-package failure; it produces no tracked deletion.

[Raw follow-up measurements and validation logs](lightweight-results/optimization-20261017/).

## Next opportunities

Stream vectored drain/rings could further reduce receive merging and packet
construction copies, with explicit leases and accepted-byte accounting. Flow-affine
execution/multiqueue may improve multiple-flow CPU use. Measure their effect on
latency and bounded memory before implementation. For remote paths, timestamps/
PAWS, RACK-TLP, PLPMTUD and recovery/fairness work remain valuable. AccECN and
negotiated ACK-rate drafts require matching peer/path support and do not replace
local I/O optimization. No new transport algorithm or unnegotiated ACK ratio is
introduced here.
